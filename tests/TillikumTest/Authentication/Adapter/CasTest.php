<?php

namespace TillikumTest\Authentication\Adapter;

use Tillikum\Authentication\Adapter;
use Zend\Http;

class CasTest extends \PHPUnit_Framework_TestCase
{
    protected $cas10;
    protected $cas20;
    protected $httpClient;
    protected $serverUri;

    public function setUp()
    {
        $this->httpClient = new Http\Client();
        $this->httpClient->setAdapter(new Http\Client\Adapter\Test());

        $this->serverUri = 'http://localhost';

        $this->cas10 = new Adapter\Cas(
            $this->httpClient,
            $this->serverUri
        );
        $this->cas10->setProtocolVersion(Adapter\Cas::CAS_1_0);

        $this->cas20 = new Adapter\Cas(
            $this->httpClient,
            $this->serverUri
        );
    }

    /**
     * @expectedException Zend\Authentication\Adapter\Exception\InvalidArgumentException
     */
    public function testUnsupportedProtocolVersion()
    {
        $this->cas10->setProtocolVersion('totally unsupported');
    }

    public function testCreateLoginUri()
    {
        $this->cas10->setLoginParameters(array('foo' => 'bar'));

        $uri = $this->cas10->createLoginUri();

        $this->assertEquals($this->serverUri . '/login?foo=bar', $uri);
    }

    public function testCreateLogoutUri()
    {
        $this->cas10->setLogoutParameters(array('foo' => 'bar'));

        $uri = $this->cas10->createLogoutUri();

        $this->assertEquals($this->serverUri . '/logout?foo=bar', $uri);
    }

    public function testCreateValidateUri()
    {
        $this->cas10->setValidateParameters(
            array(
                'service' => 'foo',
                'ticket' => 'bar',
            )
        );

        $uri = $this->cas10->createValidateUri();

        $this->assertEquals($this->serverUri . '/validate?service=foo&ticket=bar', $uri);
    }

    /**
     * @expectedException Zend\Authentication\Adapter\Exception\InvalidArgumentException
     */
    public function testValidateRequiresTicket()
    {
        $this->cas10->setValidateParameters(
            array(
                'service' => 'foo',
            )
        );

        $uri = $this->cas10->createValidateUri();
    }

    /**
     * @expectedException Zend\Authentication\Adapter\Exception\InvalidArgumentException
     */
    public function testValidateRequiresService()
    {
        $this->cas10->setValidateParameters(
            array(
                'ticket' => 'bar',
            )
        );

        $uri = $this->cas10->createValidateUri();
    }

    public function testCreateServiceValidateUri()
    {
        $this->cas20->setServiceValidateParameters(
            array(
                'service' => 'foo',
                'ticket' => 'bar',
            )
        );

        $uri = $this->cas20->createServiceValidateUri();

        $this->assertEquals($this->serverUri . '/serviceValidate?service=foo&ticket=bar', $uri);
    }

    /**
     * @expectedException Zend\Authentication\Adapter\Exception\InvalidArgumentException
     */
    public function testServiceValidateRequiresTicket()
    {
        $this->cas20->setServiceValidateParameters(
            array(
                'service' => 'foo',
            )
        );

        $uri = $this->cas20->createServiceValidateUri();
    }

    /**
     * @expectedException Zend\Authentication\Adapter\Exception\InvalidArgumentException
     */
    public function testServiceValidateRequiresService()
    {
        $this->cas20->setServiceValidateParameters(
            array(
                'ticket' => 'bar',
            )
        );

        $uri = $this->cas20->createServiceValidateUri();
    }

    public function testServerUriTrimsRightSlashes()
    {
        $this->cas20->setServerUri('http://[::1]//////');

        $this->assertEquals('http://[::1]', $this->cas20->getServerUri());
    }

    /**
     * @dataProvider validateResponseProvider
     */
    public function testValidateResponse($response, $isValid, $identity)
    {
        $this->httpClient->getAdapter()->setResponse(
            $response
        );

        $this->cas10->setValidateParameters(
            array(
                'service' => 'foo',
                'ticket' => 'bar',
            )
        );

        $result = $this->cas10->validate();

        $this->assertEquals($isValid, $result->isValid());

        if ($isValid) {
            $this->assertEquals($identity, $result->getIdentity());
        }
    }

    public function testValidateResponseWithInvalidArguments()
    {
        $this->cas10->setValidateParameters(
            array(
                'ticket' => 'bar',
            )
        );

        $result = $this->cas10->validate();

        $this->assertFalse($result->isValid());
    }

    public function testValidateResponseWithHttpFailure()
    {
        $this->httpClient->getAdapter()->setNextRequestWillFail(true);

        $this->cas10->setValidateParameters(
            array(
                'service' => 'foo',
                'ticket' => 'bar',
            )
        );

        $result = $this->cas10->validate();

        $this->assertFalse($result->isValid());
    }

    public function validateResponseProvider()
    {
        return array(
            array("HTTP/1.0 200 Aww Yeah\r\n\r\nyes\nidentity\n", true, 'identity'),
            array("HTTP/1.0 200 Aww Yeah\r\n\r\nno\n", false, ''),
            array("HTTP/1.0 200 Aww Yeah\r\n\r\n", false, ''),
            array("HTTP/1.0 200 Aww Yeah\r\n\r\n%($^#\n\n\n\n\nFS", false, ''),
            array("HTTP/1.0 400 You Idiot\r\n\r\n", false, ''),
        );
    }

    /**
     * @dataProvider serviceValidateResponseProvider
     */
    public function testServiceValidateResponse($response, $isValid, $identity)
    {
        $this->httpClient->getAdapter()->setResponse(
            $response
        );

        $this->cas20->setServiceValidateParameters(
            array(
                'service' => 'foo',
                'ticket' => 'bar',
            )
        );

        $result = $this->cas20->serviceValidate();

        $this->assertEquals($isValid, $result->isValid());

        if ($isValid) {
            $this->assertEquals($identity, $result->getIdentity());
        }
    }

    public function testServiceValidateResponseWithInvalidArguments()
    {
        $this->cas20->setServiceValidateParameters(
            array(
                'service' => 'foo',
            )
        );

        $result = $this->cas20->serviceValidate();

        $this->assertFalse($result->isValid());
    }

    public function testServiceValidateResponseWithHttpFailure()
    {
        $this->cas20->setServiceValidateParameters(
            array(
                'service' => 'foo',
                'ticket' => 'bar',
            )
        );

        $this->httpClient->getAdapter()->setNextRequestWillFail(true);

        $result = $this->cas20->serviceValidate();

        $this->assertFalse($result->isValid());
    }

    public function serviceValidateResponseProvider()
    {
        return array(
            array(
                "HTTP/1.0 200 Aww Yeah\r\n\r\n
                 <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
                   <cas:authenticationSuccess>
                     <cas:user>username</cas:user>
                     <cas:proxyGrantingTicket>PGTIOU-84678-8a9d...</cas:proxyGrantingTicket>
                   </cas:authenticationSuccess>
                 </cas:serviceResponse>",
                 true,
                 'username',
            ),
            array(
                "HTTP/1.0 200 Aww Yeah\r\n\r\n
                 <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
                   <cas:authenticationFailure code=\"INVALID_TICKET\">
                     Ticket ST-1856339-aA5Yuvrxzpv8Tau1cYQ7 not recognized
                   </cas:authenticationFailure>
                 </cas:serviceResponse>",
                false,
                '',
            ),
            array(
                "HTTP/1.0 200 Aww Yeah\r\n\r\n
                 cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
                   <cas:authenticationFailure code=\"INVALID_TICKET\">
                     Ticket ST-1856339-aA5Yuvrxzpv8Tau1cYQ7 not recognized
                   </cas:authenticationFailure>
                 </cas:serviceResponse>",
                false,
                '',
            ),
            array(
                "HTTP/1.0 400 You Idiot\r\n\r\n",
                false,
                '',
            ),
        );
    }

    public function testAuthenticateWithCas10ClientUsesValidate()
    {
        $adapter = $this->getMock(
            'Tillikum\Authentication\Adapter\Cas',
            array(
                'validate'
            ),
            array(
                $this->httpClient,
                $this->serverUri
            )
        );
        $adapter->setProtocolVersion(Adapter\Cas::CAS_1_0);

        $parameters = array('foo' => 'bar');

        $adapter->setValidateParameters($parameters);

        $adapter->expects($this->once())
                ->method('validate')
                ->with($this->equalTo($parameters));

        $adapter->authenticate();
    }

    public function testAuthenticateWithCas20ClientUsesServiceValidate()
    {
        $adapter = $this->getMock(
            'Tillikum\Authentication\Adapter\Cas',
            array(
                'serviceValidate'
            ),
            array(
                $this->httpClient,
                $this->serverUri
            )
        );

        $parameters = array('foo' => 'bar');

        $adapter->setServiceValidateParameters($parameters);

        $adapter->expects($this->once())
                ->method('serviceValidate')
                ->with($this->equalTo($parameters));

        $adapter->authenticate();
    }
}
