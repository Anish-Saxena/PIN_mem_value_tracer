A pintool to collect memory data values in addition to addresses for trace-driver simulation. 

### Compile

`g++ -o test_prog test_prog.cpp`
`make obj-intel64/champsim_tracer.so`

### Run

`../../../pin -t obj-intel64/champsim_tracer.so -t 10000 -s 11000 -o tracefile -- ./test_prog`
