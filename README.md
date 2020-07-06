# Java 8 bindings for RNP

This project provides Java 8 bindings for the [RNP high performance OpenPGP](https://github.com/rnpgp/rnp) library.

## Requirements

[RNP](https://github.com/rnpgp/rnp)

Java 1.8

## Build Instructions

1. Download, build and install shared version of the [RNP OpenPGP library](https://github.com/rnpgp/rnp).

2. Configure this project.


    ```
    cmake .
    ```

3. Build.

    ```
    make
    ```

    or

    ```
    cmake --build . --config Release
    ```
    
    Outputs are located in the _bin/Release_ and _bin/Debug_ folders.

## Testing

```
java -classpath <classpaths> tech.janky.jarop.tests.RopExamplesTest
```

## Examples

There are Java alternatives of [RNP's examples](https://github.com/rnpgp/rnp/src/examples) under the [examples](examples) folder.
