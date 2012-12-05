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
            $this->serverUri,
            Adapter\Cas::CAS_1_0
        );

        $this->cas20 = new Adapter\Cas(
            $this->httpClient,
            $this->serverUri,
            Adapter\Cas::CAS_2_0
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
        $uri = $this->cas10->createLoginUri(array('foo' => 'bar'));

        $this->assertEquals($uri, $this->serverUri . '/login?foo=bar');
    }

    public function testCreateLogoutUri()
    {
        $uri = $this->cas10->createLogoutUri(array('foo' => 'bar'));

        $this->assertEquals($uri, $this->serverUri . '/logout?foo=bar');
    }

    public function testCreateValidateUri()
    {
        $uri = $this->cas10->createValidateUri(
            array(
                'service' => 'foo',
                'ticket' => 'bar',
            )
        );

        $this->assertEquals($uri, $this->serverUri . '/validate?service=foo&ticket=bar');
    }

    /**
     * @expectedException Zend\Authentication\Adapter\Exception\InvalidArgumentException
     */
    public function testValidateRequiresTicket()
    {
        $uri = $this->cas10->createValidateUri(
            array(
                'service' => 'foo',
            )
        );
    }

    /**
     * @expectedException Zend\Authentication\Adapter\Exception\InvalidArgumentException
     */
    public function testValidateRequiresService()
    {
        $uri = $this->cas10->createValidateUri(
            array(
                'ticket' => 'bar',
            )
        );
    }

    public function testCreateServiceValidateUri()
    {
        $uri = $this->cas20->createServiceValidateUri(
            array(
                'service' => 'foo',
                'ticket' => 'bar',
            )
        );

        $this->assertEquals($uri, $this->serverUri . '/serviceValidate?service=foo&ticket=bar');
    }

    /**
     * @expectedException Zend\Authentication\Adapter\Exception\InvalidArgumentException
     */
    public function testServiceValidateRequiresTicket()
    {
        $uri = $this->cas20->createServiceValidateUri(
            array(
                'service' => 'foo',
            )
        );
    }

    /**
     * @expectedException Zend\Authentication\Adapter\Exception\InvalidArgumentException
     */
    public function testServiceValidateRequiresService()
    {
        $uri = $this->cas20->createServiceValidateUri(
            array(
                'ticket' => 'bar',
            )
        );
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

        $result = $this->cas10->validate(
            array(
                'service' => 'foo',
                'ticket' => 'bar',
            )
        );

        $this->assertEquals($isValid, $result->isValid());

        if ($isValid) {
            $this->assertEquals($identity, $result->getIdentity());
        }
    }

    public function testValidateResponseWithInvalidArguments()
    {
        $result = $this->cas10->validate(
            array(
                'ticket' => 'bar',
            )
        );

        $this->assertFalse($result->isValid());
    }

    public function testValidateResponseWithHttpFailure()
    {
        $this->httpClient->getAdapter()->setNextRequestWillFail(true);

        $result = $this->cas10->validate(
            array(
                'service' => 'foo',
                'ticket' => 'bar',
            )
        );

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

        $result = $this->cas20->serviceValidate(
            array(
                'service' => 'foo',
                'ticket' => 'bar',
            )
        );

        $this->assertEquals($isValid, $result->isValid());

        if ($isValid) {
            $this->assertEquals($identity, $result->getIdentity());
        }
    }

    public function testServiceValidateResponseWithInvalidArguments()
    {
        $result = $this->cas20->serviceValidate(
            array(
                'service' => 'foo',
            )
        );

        $this->assertFalse($result->isValid());
    }

    public function testServiceValidateResponseWithHttpFailure()
    {
        $this->httpClient->getAdapter()->setNextRequestWillFail(true);

        $result = $this->cas20->serviceValidate(
            array(
                'service' => 'foo',
                'ticket' => 'bar',
            )
        );

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
                $this->serverUri,
                Adapter\Cas::CAS_1_0
            )
        );

        $parameters = array('foo' => 'bar');

        $adapter->expects($this->once())
                ->method('validate')
                ->with($this->equalTo($parameters));

        $adapter->authenticate($parameters);
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
                $this->serverUri,
                Adapter\Cas::CAS_2_0
            )
        );

        $parameters = array('foo' => 'bar');

        $adapter->expects($this->once())
                ->method('serviceValidate')
                ->with($this->equalTo($parameters));

        $adapter->authenticate($parameters);
    }
}
