#ifndef SPDY_BYTES_H_
#define SPDY_BYTES_H_

#define BE_LOAD_16(data) (data[1] | (data[0] << 8))
#define BE_LOAD_LE_24(data) (data[0] | (data[1] ) | (data[2]))
#define BE_LOAD_24(data) (data[2] | (data[1] << 8) | (data[0] << 16))
#define BE_LOAD_32(data) (data[3] | (data[2] << 8) |            \
                          (data[1] << 16) | (data[0] << 24))

#define BE_LOAD_L(value, data, len)  \
if (len == 2) \
{\
	value = BE_LOAD_16(data);\
} else {\
	value = BE_LOAD_32(data);\
}

#define BE_STORE_16(target, source)             \
  target[1] = source & 0xFF;                    \
  target[0] = (source >> 8) & 0xFF
#define BE_STORE_LE_24(target, source)  \
  target[0] = source;         \
  target[1] = (source >> 8);  \
  target[2] = (source >> 16);
#define BE_STORE_24(target, source)  \
  target[2] = source & 0xFF;         \
  target[1] = (source >> 8) & 0xFF;  \
  target[0] = (source >> 16) & 0xFF;
#define BE_STORE_32(target, source)  \
  target[3] = source & 0xFF;         \
  target[2] = (source >> 8) & 0xFF;  \
  target[1] = (source >> 16) & 0xFF; \
  target[0] = (source >> 24) & 0xFF

#define BE_STORE_L(target, source, len)  \
if (len == 2) \
{\
	BE_STORE_16(target, source);\
} else {\
	BE_STORE_32(target, source);\
}
#endif

