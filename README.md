toss: dead simple command line file transfer
======

Toss is a convenient ultra-minimal command line tool to send files over LAN, WiFi, and [virtual networks](https://www.zerotier.com/).

## Examples

### Toss a file between two terminal windows

Sender:

    # toss nginx.conf
    nginx.conf/rpyaaaaaaaaaatevqcopx2r56xbo4bakxpjzgeh5qblmfyq4ertt3gmtnncrxyou

Receiver:

    $ catch nginx.conf/rpyaaaaaaaaaatevqcopx2r56xbo4bakxpjzgeh5qblmfyq4ertt3gmtnncrxyou
    catch: catching nginx.conf (19605 bytes)
    catch: 10.187.211.147/35824 connected, reading... wrote 19605 bytes to: nginx.conf

### Toss a file to your team

    # toss debug-output.log
    debug-output.log/vd4qaaaaaaaaabqprfnhdzwnq3r2gbakxpjzgeh5qblmfyq4ertt3gmtnncrxyou

Then paste the token into a chat system like IRC, Slack, etc.

### Stream a huge archive between systems

Sender:

    # tar -czf - /usr | toss -
    ruz7777777777777tu3pjur2yqhtmbakxpjzgeh5qblmfyq4ertt3gmtnncrxyou

Receiver:

    $ catch ruz7777777777777tu3pjur2yqhtmbakxpjzgeh5qblmfyq4ertt3gmtnncrxyou - | tar -tzf -

### Toss the output of a command to a team member

    $ ps aux | toss -
    zmr7777777777777grxowcyqr4w3gbakxpjzgeh5qblmfyq4ertt3gmtnncrxyou

Then paste the token into a chat and your team member can do this:

    $ catch zmr7777777777777grxowcyqr4w3gbakxpjzgeh5qblmfyq4ertt3gmtnncrxyou -

... and see the output of your `ps aux` command.

## Description

The `toss` program outputs a token generated from a random local TCP port, the size of the file you're sending, a hash of the file's contents (unless it's a pipe), and all the available IP addresses on all the interfaces in your system. It then listens for `catch` to connect and if presented with the correct claim token streams the file. If its input is a file it will continue to service `catch` requests one after the other (not concurrently) until it is terminated with CTRL+C or a kill signal. For pipes it terminates when the pipe closes.

The `catch` program takes a `toss` token and then attempts to connect to all the IP addresses specified in it. If connection is successful it listens for a hello message (based on the hashed token) and if this is correct sends a claim message (a different version of the hashed token). If this exchange succeeds `toss` will send the file and `catch` will receive it.

To toss a pipe, use `toss -`. To catch something and pipe it to standard output, use `catch <token> -`. Both programs send status and error messages to standard error.

The token can include a file name (the part before the slash) but this is optional. If this is not present `catch` will name the file based on its hash or the output file name provided on the command line.

Transfers are done using TCP over ports between 30000 and 65535. You may have to configure your local firewall to allow this, or at least to allow it between certain IP addresses.

Toss will work across the open Internet if no firewalls are in the way but it's mostly intended for LANs, WiFi networks, and [ZeroTier virtual networks](https://www.zerotier.com/) (plug, plug! we wrote this!). This little utility serves as an example of how easy things are if devices can communicate directly.

## Security

Toss does no encryption and authentication is based on the token alone. Files are checked against a 64-bit hash, but pipes rely on TCP CRC checking alone. If you are transferring sensitive information over an un-trusted insecure network we highly recommend encrypting it with a real crypto tool like GPG or a similar.

The `catch` command prioritizes private IP addresses and only tries globally scoped IPs after all attempts to use private ones have failed.

## Building

On Linux, Mac, and BSD just type `make`. The source is self-contained and there are no dependencies.

Some work has been done to prepare for a Windows port but this is incomplete. Pull requests are welcome.

## License

MIT license.

## Changes

 * Version 1.1: add a DESTDIR to `make install` and make toss favor ZeroTier and tun/tap interfaces over physical ones. It just lists them first so catch will try them first.
 * Version 1.0: initial release!
