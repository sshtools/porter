# porter
Tiny Java library that uses UPnP to map external WAN ports to internal LAN ports for both TCP and UDP on a supporting router.

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.sshtools/porter/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.sshtools/porter)
[![javadoc](https://javadoc.io/badge2/com.sshtools/porter/javadoc.svg)](https://javadoc.io/doc/com.sshtools/porter)
![JPMS](https://img.shields.io/badge/JPMS-com.sshtools.porter-purple)

## Features

 * Discover UPnP routers on the network.
 * Discover external IP address.
 * Map external TCP and UDP ports to internal ones.
 * Automatically unmap on JVM shutdown.
 * Requires Java 11 or above.
 * Zero runtime dependencies.
 * Graal Native Image compatible.

## Installation

Available on Maven Central, so just add the following dependency to your project's `pom.xml`.
Adjust for other build systems.

```xml
<dependency>
    <groupId>com.sshtools</groupId>
    <artifactId>porter</artifactId>
    <version>1.0.1</version>
</dependency> 
```

### JPMS

If you are using [JPMS](https://en.wikipedia.org/wiki/Java_Platform_Module_System), add `com.sshtools.porter` to your `module-info.java`.

## Usage

Usage is very simple. A port mapping can be achieved with a single line of code.

```java
UPnP.gateway().ifPresent(gw -> gw.map(80, Protocol.TCP));
```

Or to map different ports.

```java
gw.map(8080, 80, Protocol.TCP);
```

Or to unmap.

```java
gw.unmap(80, Protocol.TCP);
```

Or to test if mapped.

```java
var mapped = gw.mapped(80, Protocol.TCP);
if(mapped) {
    System.out.println("Mapped!");
}
else {
    System.out.println("Not Mapped!");
}
```

For more control over the discovery process, instead of usage, `UPnP.gateway()`, use `DiscoveryBuilder`.
You can use this to configure, monitor discovery, list all gateways and more.

```java
try(var discovery = new UPnP.DiscoveryBuilder().
    withoutShutdownHooks().
    onGateway(gw -> {
        System.out.format("Gateway found %s%n", gw.ip());
    }).
    build()) {
    
    /* Not strictly needed, here from demonstrations purposes */
    discovery.awaitCompletion();
    
    /* gateways() will wait till complete */
    var count = discovery.gateways().size();
    System.out.format("Found %d gateways%n", count);
}
```
