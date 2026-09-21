# sign-07 CS — universal forgery

`forgery.c` is a universal forgery against CS: it produces a signature that the
submission's own `sig_verify()` accepts, on a message that was never signed,
without the secret key.

## Compile

```sh
make -C ../api harness
make -C . libs
make -C . exploit
```

## Run

End-to-end forgery (scaled-down instance, seconds):

```sh
./forgery_CS-128-scaled-tau3 lib/libCS-128-scaled-tau3.so --threads 8 --verbose
```

Submitted parameter sets:

```sh
./forgery_CS-128 lib/libCS-128.so --control --threads 8 --verbose
./forgery_CS-256 lib/libCS-256.so --control --threads 8 --verbose
./forgery_CS-512 lib/libCS-512.so --control --threads 8 --verbose
```

Options: `--trials N` grind budget, `--threads N`, `--control` (expect the
grind to run out of budget), `--verbose`.

Or through the repository runner:

```sh
tools/reproduce.sh sign-07
```
