# -*- coding: utf-8 -*-

class poly1305(object):
	def __init__(self, key, tagSize=16):
		self.tagSize = tagSize
		self.buffer = [0]*tagSize
		self.leftover = 0
		self.r = [0]*10
		self.h = [0]*10
		self.pad = [0]*8
		self.finished = 0
		t = [0]*8
		i = 0

		for i in range(8):
			t[i] = poly1305.U8TO16(key, i*2)

		self.r[0] =   t[0]                        & 0x1fff
		self.r[1] = ((t[0] >> 13) | (t[1] <<  3)) & 0x1fff
		self.r[2] = ((t[1] >> 10) | (t[2] <<  6)) & 0x1f03
		self.r[3] = ((t[2] >>  7) | (t[3] <<  9)) & 0x1fff
		self.r[4] = ((t[3] >>  4) | (t[4] << 12)) & 0x00ff
		self.r[5] =  (t[4] >>  1)                 & 0x1ffe
		self.r[6] = ((t[4] >> 14) | (t[5] <<  2)) & 0x1fff
		self.r[7] = ((t[5] >> 11) | (t[6] <<  5)) & 0x1f81
		self.r[8] = ((t[6] >>  8) | (t[7] <<  8)) & 0x1fff
		self.r[9] =  (t[7] >>  5)                 & 0x007f

		for i in range(8):
				self.h[i] = 0
				self.pad[i] = poly1305.U8TO16(key, 16+(2*i))
		self.h[8] = 0
		self.h[9] = 0
		self.leftover = 0
		self.finished = 0

	def blocks(self, m, mpos, b):
		hibit = 0 if self.finished else (1 << 11)
		t = [0]*8
		d = [0]*10
		c = 0
		i = 0
		j = 0

		while (b >= self.tagSize):
			for i in range(8):
				t[i] = poly1305.U8TO16(m, i*2+mpos)

			self.h[0] +=   t[0]                        & 0x1fff;
			self.h[1] += ((t[0] >> 13) | (t[1] <<  3)) & 0x1fff;
			self.h[2] += ((t[1] >> 10) | (t[2] <<  6)) & 0x1fff;
			self.h[3] += ((t[2] >>  7) | (t[3] <<  9)) & 0x1fff;
			self.h[4] += ((t[3] >>  4) | (t[4] << 12)) & 0x1fff;
			self.h[5] +=  (t[4] >>  1)                 & 0x1fff;
			self.h[6] += ((t[4] >> 14) | (t[5] <<  2)) & 0x1fff;
			self.h[7] += ((t[5] >> 11) | (t[6] <<  5)) & 0x1fff;
			self.h[8] += ((t[6] >>  8) | (t[7] <<  8)) & 0x1fff;
			self.h[9] +=  (t[7] >>  5)                 | hibit;

			c = 0
			for i in range(10):
				d[i] = c
				for j in range(10):
					d[i] = d[i] + (self.h[j] & 0xffffffff) * (self.r[i-j] if (j <= i) else (5 * self.r[i+10-j]))
					if j == 4:
						c = (d[i] >> 13)
						d[i] = d[i] & 0x1fff
				c = c + (d[i] >> 13)
				d[i] = d[i] & 0x1fff
			c = ((c << 2) + c)
			c = c + d[0]
			d[0] = ((c & 0xffff) & 0x1fff)
			c = (c >> 13)
			d[1] += c

			for i in range(10):
				self.h[i] = d[i] & 0xffff

			mpos = mpos + self.tagSize
			b = b - self.tagSize


	def finish(self):
		g = [0]*10
		c = 0
		mask = 0
		f = 0
		i = 0

		if self.leftover:
			i = self.leftover
			self.buffer[i] = 1
			i = i + 1
			for i in range(i, self.tagSize):
				self.buffer[i] = 0

			self.finished = 1
			self.blocks(self.buffer, 0, self.tagSize)

		c = self.h[1] >> 13
		self.h[1] = self.h[1] & 0x1fff
		for i in range(2, 10):
			self.h[i] = self.h[i] + c
			c = self.h[i] >> 13
			self.h[i] = self.h[i] & 0x1fff
		self.h[0] = self.h[0] + (c * 5)
		c = self.h[0] >> 13
		self.h[0] = self.h[0] & 0x1fff
		self.h[1] = self.h[1] + c
		c = self.h[1] >> 13
		self.h[1] = self.h[1] & 0x1fff
		self.h[2] = self.h[2] + c

		g[0] = self.h[0] + 5
		c = g[0] >> 13
		g[0] = g[0] & 0x1fff
		for i  in range(1, 10):
			g[i] = self.h[i] + c
			c = g[i] >> 13
			g[i] = g[i] & 0x1fff
		g[9] = g[9] - (1 << 13)
		g[9] = g[9] & 0xffff

		mask = (g[9] >> 15) - 1
		for i in range(10):
			g[i] = g[i] & mask
		mask = ~mask
		for i in range(10):
			self.h[i] = (self.h[i] & mask) | g[i]

		self.h[0] = ((self.h[0]      ) | (self.h[1] << 13)) & 0xffff
		self.h[1] = ((self.h[1] >>  3) | (self.h[2] << 10)) & 0xffff
		self.h[2] = ((self.h[2] >>  6) | (self.h[3] <<  7)) & 0xffff
		self.h[3] = ((self.h[3] >>  9) | (self.h[4] <<  4)) & 0xffff
		self.h[4] = ((self.h[4] >> 12) | (self.h[5] <<  1) | (self.h[6] << 14)) & 0xffff
		self.h[5] = ((self.h[6] >>  2) | (self.h[7] << 11)) & 0xffff
		self.h[6] = ((self.h[7] >>  5) | (self.h[8] <<  8)) & 0xffff
		self.h[7] = ((self.h[8] >>  8) | (self.h[9] <<  5)) & 0xffff
		
		f = (self.h[0] & 0xffffffff) + self.pad[0]
		self.h[0] = f & 0xffff
		for i in range(1, 8):
			f = (self.h[i] & 0xffffffff) + self.pad[i] + (f >> 16)
			self.h[i] = f & 0xffff

		mac = [0]*self.tagSize
		for i in range(8):
			poly1305.U16TO8(mac, i*2, self.h[i])
			self.pad[i] = 0
		for i in range(10):
			self.h[i] = 0
			self.r[i] = 0
		return mac

	def update(self, m, b=None):
		if b is None:
			b = len(m)
		want = 0
		i = 0
		mpos = 0

		if self.leftover:
			want = self.tagSize - self.leftover
			if want > b:
				want = b
			for i in reversed(range(want)):
				self.buffer[self.leftover+i] = m[i+mpos]
			b = b - want
			mpos = mpos + want
			self.leftover = self.leftover + want
			if self.leftover < self.tagSize:
				return
			self.blocks(self.buffer, 0, self.tagSize)
			self.leftover = 0

		if b >= self.tagSize:
			want = (b & ~(self.tagSize - 1))
			self.blocks(m, mpos, want)
			mpos = mpos + want
			b = b - want

		if b:
			for i in reversed(range(b)):
				self.buffer[self.leftover+i] = m[i+mpos]
			self.leftover = self.leftover + b

	@staticmethod
	def U8TO16(p, pos):
		return ((p[pos] & 0xff) & 0xffff) | (((p[pos+1] & 0xff) & 0xffff) << 8)

	@staticmethod
	def U16TO8(p, pos, v):
		p[pos]   = (v     ) & 0xff
		p[pos+1] = (v >> 8) & 0xff
