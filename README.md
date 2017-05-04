toss: dead simple LAN file transfers from the command line
======

Toss is a convenient tool to send files over local area networks.

The `toss` program outputs a token generated from a random local TCP port, the size of the file you're sending, a hash of the file's contents (unless it's a pipe), and all the available IP addresses on all the interfaces in your system. It then listens for `catch`. It will continue to service `catch` requests until it is terminated with CTRL+C or a kill signal.

The `catch` program takes a `toss` token and then attempts to connect to all the IP addresses specified in it. If connection is successful it listens for a hello message (based on the hashed token) and if this is correct sends a claim message (a different version of the hashed token). If the sender gets the claim, it sends the file and terminates. The receiver receives and writes the file and then verifies the hash, informing you in the file appears okay.

To toss a pipe, use `toss -`. To catch something and pipe it to standard output, use `catch <token> -`.

The token includes a file name (before the slash) but this is optional. If you only send the part after the slash the file will be named after it's hash unless an output name is explicitly provided to `catch`.

Transfers are done using TCP over ports between 30000 and 65535. You may have to configure your local firewall to allow this, or at least to allow it between certain IP addresses.

Toss will work across the open Internet if no firewalls are in the way, but it's mostly intended for LANs, WiFi networks, and [ZeroTier virtual networks](https://www.zerotier.com/) (plug, plug! we wrote this!). This is the kind of easy, convenient thing that's possible if devices can communicate with one another directly.

## Security

Toss does no encryption and authentication is based on the token alone. If you are transferring sensitive information over an un-trusted network we highly recommend you encrypt it with GPG or a similar tool. It's intended for use on secure networks.

The `catch` command prioritizes private IP addresses and only tries globally scoped IPs after all attempts to use private ones have failed.

## Examples

### Toss a file between two terminal windows

### Toss a file to your team

### Send something to an IRC channel from a VPS

### Stream a huge archive between systems
