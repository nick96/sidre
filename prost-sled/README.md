# prost-sled: An integration layber between prost and sled

`prost-sled` makes it easy to use `sled` to store structure data (protobufs)
encoded using `prost`. It just abstracts away the boilerplate of having to
encode and decode them.