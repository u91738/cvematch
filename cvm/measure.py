#!/usr/bin/python3

import sys
from gensim.models.keyedvectors import KeyedVectors
import pyopencl as cl
import numpy as np
from typing import Optional, List, Union
from pathlib import Path


class OCLInput:
    '''Input to OpenCL kernel. Reuses the buffers where possible'''

    def __init__(self, ctx:cl.Context, queue:cl.CommandQueue, value:Optional[np.ndarray]=None):
        self.ctx = ctx
        self.queue = queue
        self.buf = None
        self.used_size = None
        if value is not None:
            self.assign(value)

    def __alloc(self, value:np.ndarray, size:int):
        assert size > 0
        if self.buf is not None:
            self.buf.release()
        flags = cl.mem_flags.HOST_WRITE_ONLY | cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR
        self.buf = cl.Buffer(self.ctx, flags, size, value)

    def assign(self, value:np.ndarray):
        assert isinstance(value, np.ndarray)
        size = value.itemsize * np.prod(value.shape)
        if self.buf is None or self.buf.size <= size:
            self.__alloc(value, size)
        else:
            cl.enqueue_copy(self.queue, self.buf, value)
        self.used_size = size

    def __enter__(self):
        return self

    def __exit__(self, t, v, bt):
        if self.buf is not None:
            self.buf.release()


class OCLOutput:
    '''Output from OpenCL kernel. Reuses the buffers where possible'''

    def __init__(self, ctx:cl.Context, queue:cl.CommandQueue, dtype, count:Optional[int]=None):
        self.buf = None
        self.used_count = None
        self.itemsize = dtype().itemsize
        self.dtype = dtype
        self.ctx = ctx
        self.queue = queue
        if count is not None:
            self.resize(count)

    def __alloc(self, count:int):
        if self.buf is not None:
            self.buf.release()
        flags = cl.mem_flags.HOST_READ_ONLY | cl.mem_flags.WRITE_ONLY
        self.buf = cl.Buffer(self.ctx, flags, size=count * self.itemsize)
        self.used_count = count

    def resize(self, count):
        if self.buf is None or self.buf.size < count * self.itemsize:
            self.__alloc(count)
        else:
            self.used_count = count

    def get(self):
        r = np.empty((self.used_count,), dtype=self.dtype)
        cl.enqueue_copy(self.queue, r, self.buf)
        return r

    def __enter__(self):
        return self

    def __exit__(self, t, v, bt):
        if self.buf is not None:
            self.buf.release()


def w2v_get_index(w2v, token):
    r = w2v.key_to_index.get(token)
    return -1 if r is None else r


class Needles:
    '''What to search. Knows how to pack itself for OpenCL kernel'''

    def __init__(self, ctx:cl.Context, queue:cl.CommandQueue, w2v:KeyedVectors, needles:List[List[str]]):
        tmp_needles = []
        tmp_needle_offsets = []
        for needle in needles:
            tmp_needle_offsets.append(len(tmp_needles))
            tmp_needles.append(len(needle))
            for i in needle:
                tmp_needles.append(w2v_get_index(w2v, i))
        self.count = len(needles)
        self.needles = OCLInput(ctx, queue, np.array(tmp_needles, np.int32))
        self.offsets = OCLInput(ctx, queue, np.array(tmp_needle_offsets, np.int32))

    def __enter__(self):
        self.needles.__enter__()
        self.offsets.__enter__()
        return self

    def __exit__(self, t, v, bt):
        self.needles.__exit__(t, v, bt)
        self.offsets.__exit__(t, v, bt)


class Haystack:
    '''Where to search'''

    def __init__(self, ctx:cl.Context, queue:cl.CommandQueue, w2v:KeyedVectors):
        self.buf = OCLInput(ctx, queue)
        self.w2v = w2v
        self.count = None

    def assign(self, haystack:List[str]):
        assert len(haystack) < 32768, 'TODO: allow dynamic size of haystack'
        hs_inds = np.array([w2v_get_index(self.w2v, i) for i in haystack], np.int32)
        self.buf.assign(hs_inds)
        self.count = len(haystack)

    def __enter__(self):
        self.buf.__enter__()
        return self

    def __exit__(self, t, v, bt):
        self.buf.__exit__(t, v, bt)


class LevensteinSearchCL:
    '''Wrapper for OpenCL kernel with main search logic. Mostly manages resources'''

    def __init__(self, w2v:KeyedVectors, haystack_max:int, del_cost:int, ins_cost:int, default_dist:int):
        self.w2v = w2v

        self.ctx = cl.create_some_context(interactive=False)

        is_le = sys.byteorder == 'little'
        assert all(i.endian_little == is_le for i in self.ctx.devices), 'This code assumes that host and OpenCL device have the same endianess'

        self.queue = cl.CommandQueue(self.ctx)
        self.dictionary = OCLInput(self.ctx, self.queue, w2v.vectors)

        self.dist = OCLOutput(self.ctx, self.queue, np.float32)
        self.ind = OCLOutput(self.ctx, self.queue, np.uint32)

        with open(Path(__file__).parent / 'levenstein.cl', 'r') as src_file:
            self.program = cl.Program(self.ctx, src_file.read())\
                             .build(options=[
                                '-D', f'DEL_COST={del_cost}',
                                '-D', f'INS_COST={ins_cost}',
                                '-D', f'DEFAULT_DISTANCE={default_dist}',
                                '-D', f'HAYSTACK_MAX={haystack_max + 1}',
                                '-D', f'VECTOR_SIZE={w2v.vector_size}',
                             ])

    def prepare_needles(self, needles):
        return Needles(self.ctx, self.queue, self.w2v, needles)

    def prepare_haystack(self):
        return Haystack(self.ctx, self.queue, self.w2v)

    def __enter__(self):
        self.dist.__enter__()
        self.ind.__enter__()
        self.dictionary.__enter__()
        return self

    def __exit__(self, t, v, bt):
        self.dist.__exit__(t, v, bt)
        self.ind.__exit__(t, v, bt)
        self.dictionary.__exit__(t, v, bt)

    def search(self, needles:Needles, haystack:Haystack):
        assert isinstance(haystack, Haystack)
        assert isinstance(needles, Needles)

        self.dist.resize(needles.count)
        self.ind.resize(needles.count)

        self.program.levenstein_score_all_needles(
            self.queue, (needles.count,), None,
            self.dictionary.buf, np.uint32(len(self.w2v.vectors)),
            needles.needles.buf,
            needles.offsets.buf,
            haystack.buf.buf, np.uint32(haystack.count),
            self.dist.buf,
            self.ind.buf)
        return self.dist.get(), self.ind.get()
