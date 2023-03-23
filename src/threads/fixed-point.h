#include<stdint.h>
const int f = 2<<14; // f for 17.14 fixed-point number

static inline int 
itof(int n){
    return n * f;
}

static inline int
ftoi_zero(int x){
    return x / f;
}

static inline int
ftoi_round(int x){
    return x>=0 ? ((x+f/2)/f) : ((x-f/2)/f);
}

/* Add a fixed-point number and an integer, returning fixed-point number */
static inline int
add_fi(int x, int n){
    return x + n * f;
}

static inline int
mul_ff(int x, int y){
    return ((int64_t)x) * y / f;
}

static inline int
mul_fi(int x, int n){
    return x * n;
}

static inline int
div_ff(int x, int y){
    return ((int64_t)x) * f / y;
}

static inline int
div_fi(int x, int n){
    return x / n;
}

