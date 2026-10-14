# To change the cuda arch, edit Makefile.am and run ./build.sh

extracflags="-march=native -D_REENTRANT -falign-functions=16 -falign-jumps=16 -falign-labels=16"

if [ -z "$CUDA_PATH" ]; then
	if command -v nvcc >/dev/null 2>&1; then
		CUDA_PATH=$(dirname $(dirname $(which nvcc)))
	else
		CUDA_PATH="/usr/local/cuda"
	fi
fi

CUDA_CFLAGS="-O3 -lineno -Xcompiler -Wall -D_FORCE_INLINES" \
	./configure CXXFLAGS="-O3 $extracflags" --with-cuda="$CUDA_PATH" --with-nvml=libnvidia-ml.so

