# CAS authentication adapter for Zend Framework 2

CAS is an authentication system originally created by Yale University to provide
a trusted way for an application to authenticate a user.

[http://www.jasig.org/cas/](http://www.jasig.org/cas/)

## Requirements

* Zend Framework 2 HTTP client
* Zend Framework 2 Authentication framework

## Installation

Add this repository to your `composer.json`:

```json
{
    "require": {
        "tillikum/zf2-cas-authentication-adapter": "~0.0"
    }
}
```

then `composer update`.

## Usage

```php
<?php

use Tillikum\Authentication\Adapter\Cas as CasAdapter;
use Zend\Authentication;
use Zend\Http;

$httpClient = new Http\Client();

/** Standalone **/

$adapter = new CasAdapter(
    $httpClient,
    'http://localhost/cas'
);

// You'll need to do this in response to requests to your system:
$adapter->setServiceValidateParameters(
    array(
        'service' => 'http://my/current/url',
        'ticket' => 'ST-ACME-123',
    )
);

$result = $adapter->authenticate();

/** Plugged in to Zend\Authentication **/

// Assuming we're still using the $adapter constructed above:

$authService = new Authentication\AuthenticationService(
    new Authentication\Storage\NonPersistent(),
    $adapter
);

$result = $authService->authenticate();
```

## Troubleshooting

### SSL problems when talking to a CAS server

You can pass any options you like or need to the `Zend\Http\Client`. One example
below may be necessary to give an absolute CA path for your environment:

```php
<?php

$httpClient = new Zend\Http\Client();
$httpClient->setOptions(
    array(
        'sslcapath' => '/etc/ssl/certs'
    )
);

// ... Pass the modified HTTP client to the adapter as usual ...
```
