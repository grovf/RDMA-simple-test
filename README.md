# RDMA simple test

This project is a test application illustrating RDMA communication between an initiator and a target over a Reliable Connection (RC).

## Build Instructions
This project uses a CMake-based build system. To build:
```
mkdir build
cd build
cmake .. && make
```

## Usage
Once built, you can run the application to test RDMA communication.

## Example

Initiator:
```
./rdma_simple_test -N rxe0 -L 192.168.0.131 -R 192.168.0.132 -I 1
```

Target:
```
./rdma_simple_test -N rxe0 -L 192.168.0.131 -R 192.168.0.132 -I 0
```

## Command-line Options
To see the full list of available command-line parameters and their descriptions, run:
```
./rdma_simple_test --help
```

## Notes
- Replace rxe0 with your RDMA device name.
- Ensure RDMA drivers and configuration are correctly set up.