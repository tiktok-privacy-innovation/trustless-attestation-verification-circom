# Known Issues

We observed several known issues during development:

- Javascript heap out of memory: Please do `export NODE_OPTIONS=--max_old_space_size=16384` or any value suitable. This could happen when the size of the key generation phase requires more memory than expected.
- Segmentation fault when generating the witness: Please increase the stack limits on your machine to, e.g., unlimited by `ulimit -s unlimited`. This is because we hardcode the power of generators on the curve to accelarate the witness generation but this would require large stack space available.
- Endianess: Please be extra careful when dealing with the inputs. This is because the circuit uses a different encoding mechanism based on strides, each of which consists of *6 bytes*. This can add additional confusion when doing encoding. By default, everything should be big endian.
