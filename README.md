# PCM Stinger

This is a fork of the [OWASP Stinger Project](https://www.owasp.org/index.php/Stinger)
to support the needs of PCM projects.

## Developer notes

This project is managed through Maven and all project settings can be found in
`pom.xml`. The original project structure is maintained to make it easier to
keep up with upstream changes but, in general, just ignore:

    build.xml
    changes.txt
    /.classpath
    /.project
    /.settings/
    /bin/
    /build/
    /dist/
    /lib/

The default branch, `master`, will contain the main line of development. The
`upstream` branch tracks any releases from OWASP. Any releases from OWASP shall
be applied in its entirety to the `upstream` branch before being merged into
master.
