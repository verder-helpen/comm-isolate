# 24sessions communication plugin for Verder Helpen

This respository is a part of the Verder Helpen Platform. It contains a communication plugin useable for
communication platforms that only want to display a users attribute to helpdesk employees. This is
useful for minimizing implementation complexity and regulatory requirements on the communication platform
itself.

This implementation is intended as a reference for other video conferencing plugins. It aims to keep the
video conferencing software as agnostic as possible to Verder Helpen, by implementing only the minimally required interaction.

The plugin consists of 2 parts:

- The plugin backend, which is responsible for talking to the rest of the Verder Helpen ecosystem as well as redirecting guest users to the location where they can initiate the authentication process.
- The attribute display, which is responsible for displaying attributes in an iframe embedded in the interface for the service employee.

The plugin is written in [Rust](https://www.rust-lang.org/).

## Getting started

To build and run this plugin backend run:
```
ROCKET_CONFIG=config.sample.toml cargo run
```

The attribute UI can be built by:
```
cd attribute-ui
yarn
yarn run build
```

Setup a Postgres database and execute `schema.sql`.

Configure the applicable domains and credentials in:

- `config.sample.toml`

You will need a webserver (like NGINX) to serve static files and perform the necessary routing. 

## Further reading

Complete documentation for this plugin can be found in [the general Verder Helpen documentation](https://docs.verderhelpen.nl)
