# Extract PKZIP from HTTP

Extract only the files you need from a zip using HTTP range requests.

The library is very minimal and may not support all types of zip formats.

Uses [ureq](https://github.com/algesten/ureq) and is blocking. For the async counterpart see [ziponline](https://github.com/ogghostjelly/ziponline) (ziponline is not a drop-in replacement, it has a similar but different api).

# Limitations

Currently only supports DEFLATE decompression and only supports EOCD headers that are less than 256 bytes in size.

# Examples

```rust
let mut reader = ziponhttp::extract_file(
    agent,         // ureq::Agent
    url,           // url to zip file
    filesize,      // size of zip file (can be set to None).
    "filename.txt" // file to extract
)?;

io::copy(&mut reader, ...);
```

```rust
let zipfile = ziponhttp::ZipReader::get(
    agent,         // ureq::Agent
    url,           // url to zip file
    filesize,      // size of zip file (can be set to None).
)?;

for file in zipfile {
    let file = file?;
    if file.filename.ends_with(".txt") {
        let rdr = ziponhttp::read_file(agent, url, &file)?;
        let content = io::read_to_string(rdr)?;
        println!("The text file says: {content}");
    }
}
```