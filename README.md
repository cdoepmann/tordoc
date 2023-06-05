# tordoc

A parser for Tor docs, written in Rust.

This crate implements parsing of Tor documents as specified in
[dir-spec](https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/dir-spec.txt).
For now, this crate only parses consensus documents (`@type network-status-consensus-3`)
and full relay descriptors (`@type server-descriptor`).
Also, only a very limited subset of data is parsed.

Please be aware that the API is currently _very_ unfinished and will likely
change soon in an incompatible way.

## Documentation

As this crate isn't currently on crates.io, it also isn't on docs.rs.
Therefore, in order to view the API documentation,
clone this repo and run `cargo doc --open`.

## License

This project is licensed under the terms of the MIT License,
as well as the Apache 2.0 License.
You are free to choose whichever suits your needs best.
