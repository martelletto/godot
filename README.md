# godot
godot is a tool for generating and verifying digital signatures, with a
focus on simplicity and the adoption of best practices.

As it stands, 4096-bit RSA probabilistic signatures (PSS) are
supported. The digest mechanism used is SHA-256, and the PSS salt
length is taken to be same size as a SHA-256 digest. Except where
otherwise noted, the following pairs of commands are understood to
be equivalent in functionality:

- openssl genrsa -out privkey.pem 4096
- godot rsa new -o privkey.pem

godot uses /dev/urandom for key and salt material. It also ensures
that privkey.pem is only accessible to the current user (mode 600).

- openssl rsa -in privkey.pem -pubout -out pubkey.pem
- godot rsa pub -i privkey.pem -o pubkey.pem

godot refuses to work with private keys if they are not mode 600.

- openssl sha -sign privkey.pem -out signature.bin -sha256 -sigopt digest:sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 < file
- godot rsa sign -k privkey.pem -i file -o signature.bin

- openssl -verify pubkey.pem -signature signature.bin -sha256 -sigopt digest:sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 < file
- godot rsa verify -k privkey.pem -k pubkey.pem -s signature.bin -i file

godot started as an otherwise uncompromising exercise by the author
to master the Go language. Use it at your own risk.
