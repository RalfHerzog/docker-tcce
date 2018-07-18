# Docker-TCCE

Dockerized image with exporter for the tcce-library.

## What is it good for?

With [tcce](https://github.com/RalfHerzog/tcce) we can query and generate easy
accessible entities from [traefik's](https://traefik.io/) consul acme storage.
The idea is to export your valid Let's Encrypt certificates into a specific
directory to make it usable for other applications like

* Mailserver
* FTP-Server
* LDAP
* and all other services not covered by traefik

## Installation

You will need a docker runtime to run containers of this image.

## Usage

    $ docker-compose up

In `docker-compose.yml` you can control the export via environment variables.

    CRON_PATTERN: 28 3 * * *

Run the export of certificates each day at 03:28 AM. Cron patterns are accepted. For more detail have a look at [jmettraux/rufus-scheduler](https://github.com/jmettraux/rufus-scheduler)

    FIRST_IN: 10s

In development you likely do not want to want a day for a export. Define a time period to wait for a single execution. For more detail have a look at [jmettraux/rufus-scheduler](https://github.com/jmettraux/rufus-scheduler)

    CONSUL_URL: http://dc1.consul:8300

The URL to your running Consul-Server(s)

    CONSUL_ACL_TOKEN: xxxxxxxx-yyyy-zzzz-1111-222222222222

We need a Consul ACL Token to query the ACME object (see `CONSUL_KV_PATH`)

`CONSUL_KV_PATH: traefik/acme/account/object`

The Consul path to the acme account object written by traefik

    CA_FILE: /usr/src/app/ca.crt

You can provide a CA-Certificate to communicate with your Consul server (see `CONSUL_URL`)

    EXPORT_DIRECTORY: /export

Define a directory to export the certificates to. The directory should be mounted inside the container so that you can access you certificates externally

    EXPORT_OVERWRITE: true

If traefik renews a certificate, you may want to overwrite the old one. `true` is the default

    LOG_LEVEL: INFO

Control the log level to the container-console

    TZ: Europe/Berlin

To schedule the correct time, you have to tell me in which timezone you reside to. For more detail have a look at [jmettraux/rufus-scheduler](https://github.com/jmettraux/rufus-scheduler)

## Development

After checking out the repo, you can run `ruby main.rb` or build a new docker image via

    $ docker build -t ralfherzog/tcce .

and run it with

    $ docker run -it ralfherzog/tcce

or with docker-compose

    $ docker-compose build
    $ docker-compose up

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/RalfHerzog/tcce. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the docker-tcce project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/RalfHerzog/docker-tcce/blob/master/CODE_OF_CONDUCT.md).
