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
        "tillikum/zf2-cas-authentication/adapter": "dev-master"
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

// Standalone

$adapter = new CasAdapter(
    $httpClient,
    'http://localhost/cas'
);

$result = $adapter->authenticate(
    array(
        'service' => 'http://my/current/url',
        'ticket' => 'ST-ACME-123',
    )
);

// Plugged in to Zend\Authentication

$authService = new Authentication\AuthenticationService(
    new Authentication\Storage\NonPersistent(),
    $adapter
);

$result = $authService->authenticate(
    array(
        'service' => 'http://my/current/url',
        'ticket' => 'ST-ACME-123',
    )
);
```
