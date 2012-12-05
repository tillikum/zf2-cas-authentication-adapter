<?php
/**
 * The Tillikum Project (http://tillikum.org/)
 *
 * @link       http://tillikum.org/websvn/
 * @copyright  Copyright 2009-2012 Oregon State University (http://oregonstate.edu/)
 * @license    http://www.gnu.org/licenses/gpl-2.0-standalone.html GPLv2
 */

namespace Tillikum\Authentication\Adapter;

use Zend\Authentication;
use Zend\Authentication\Adapter;
use Zend\Http;

class Cas implements Adapter\AdapterInterface
{
    /**
     * CAS 2.0 XML namespace
     */
    const XML_NS_2_0 = 'http://www.yale.edu/tp/cas';

    /**
     * CAS protocol version 1.0
     */
    const CAS_1_0 = '1.0';

    /**
     * CAS protocol version 2.0
     */
    const CAS_2_0 = '2.0';

    /**
     * Parameters required for the /login endpoint
     *
     * See protocol document section 2.1.1
     *
     * @see http://www.jasig.org/cas/protocol
     * @var array
     */
    protected static $requiredLoginParameters = array();

    /**
     * Parameters required for the /logout endpoint
     *
     * See protocol document section 2.3.1
     *
     * @see http://www.jasig.org/cas/protocol
     * @var array
     */
    protected static $requiredLogoutParameters = array();

    /**
     * Parameters required for the /serviceValidate endpoint
     *
     * See protocol document section 2.5.1
     *
     * @see http://www.jasig.org/cas/protocol
     * @var array
     */
    protected static $requiredServiceValidateParameters = array(
        'service',
        'ticket',
    );

    /**
     * Parameters required for the /validate endpoint
     *
     * See protocol document section 2.4.1
     *
     * @see http://www.jasig.org/cas/protocol
     * @var array
     */
    protected static $requiredValidateParameters = array(
        'service',
        'ticket',
    );

    /**
     * HTTP client used to connect to the CAS server
     *
     * @var Http\Client
     */
    protected $httpClient;

    /**
     * CAS protocol version
     *
     * @var string
     */
    protected $protocolVersion;

    /**
     * CAS server base URI
     *
     * @var string
     */
    protected $serverUri;

    /**
     * @param Http\Client $httpClient
     * @param string      $serverUri
     * @param string      $protocolVersion
     */
    public function __construct(
        Http\Client $httpClient,
        $serverUri,
        $protocolVersion = self::CAS_2_0
    ) {
        $this->httpClient = $httpClient;

        $this->setServerUri($serverUri);
        $this->setProtocolVersion($protocolVersion);
    }

    /**
     * Authenticate against a configured CAS server
     *
     * @param  array            $parameters boolean
     * @return Zend_Auth_Result
     */
    public function authenticate(array $parameters = array())
    {
        switch ($this->protocolVersion) {
            case self::CAS_1_0:
                return $this->validate($parameters);
                break;
            case self::CAS_2_0:
                return $this->serviceValidate($parameters);
                break;
            default:
                return new Authentication\Result(
                    Authentication\Result::FAILURE,
                    '',
                    array(
                        'Invalid version or no version set.'
                    )
                );
                break;
        }
    }

    /**
     * @return string
     */
    public function createLoginUri(array $parameters)
    {
        return $this->createUri(
            'login',
            self::$requiredLoginParameters,
            $parameters
        );
    }

    /**
     * @return string
     */
    public function createLogoutUri(array $parameters)
    {
        return $this->createUri(
            'logout',
            self::$requiredLogoutParameters,
            $parameters
        );
    }

    /**
     * @return string
     */
    public function createServiceValidateUri(array $parameters)
    {
        return $this->createUri(
            'serviceValidate',
            self::$requiredServiceValidateParameters,
            $parameters
        );
    }

    /**
     * @return string
     */
    public function createValidateUri(array $parameters)
    {
        return $this->createUri(
            'validate',
            self::$requiredValidateParameters,
            $parameters
        );
    }

    /**
     * @return string
     */
    public function getProtocolVersion()
    {
        return $this->protocolVersion;
    }

    /**
     * @return string
     */
    public function getServerUri()
    {
        return $this->serverUri;
    }

    /**
     * @param  array                $parameters
     * @return Authentication\Result
     */
    public function serviceValidate(array $parameters)
    {
        try {
            $uri = $this->createServiceValidateUri($parameters);
        } catch (Adapter\Exception\InvalidArgumentException $e) {
            return new Authentication\Result(
                Authentication\Result::FAILURE,
                '',
                array($e->getMessage())
            );
        }

        $this->httpClient->resetParameters();
        $this->httpClient->setUri($uri);

        try {
            $response = $this->httpClient->send();
        } catch (Http\Exception\RuntimeException $e) {
            return new Authentication\Result(
                Authentication\Result::FAILURE_UNCATEGORIZED,
                '',
                array(
                    $e->getMessage()
                )
            );
        }

        if (!$response->isSuccess()) {
            return new Authentication\Result(
                Authentication\Result::FAILURE_UNCATEGORIZED,
                '',
                array(
                    'HTTP response did not indicate success.'
                )
            );
        }

        $body = $response->getBody();

        $previousErrorSetting = libxml_use_internal_errors(true);
        $simpleXmlElement = simplexml_load_string($body, 'SimpleXMLElement', 0, self::XML_NS_2_0);

        if ($simpleXmlElement === false) {
            $errors = array();
            foreach (libxml_get_errors() as $xmlError) {
                $errors[] = $xmlError->message;
            }

            libxml_clear_errors();
            libxml_use_internal_errors($previousErrorSetting);

            return new Authentication\Result(
                Authentication\Result::FAILURE_UNCATEGORIZED,
                '',
                $errors
            );
        }

        libxml_use_internal_errors($previousErrorSetting);

        if (isset($simpleXmlElement->authenticationFailure)) {
            $errors = array();
            foreach ($simpleXmlElement->authenticationFailure as $failure) {
                $errors[] = sprintf(
                    '%s: %s',
                    trim($failure->attributes()->code),
                    trim($failure)
                );
            }

            return new Authentication\Result(
                Authentication\Result::FAILURE_UNCATEGORIZED,
                '',
                $errors
            );
        }

        if (empty($simpleXmlElement->authenticationSuccess)) {
            return new Authentication\Result(
                Authentication\Result::FAILURE_UNCATEGORIZED,
                '',
                array(
                    'authenticationSuccess was not found in the server response.'
                )
            );
        }

        return new Authentication\Result(
            Authentication\Result::SUCCESS,
            (string) $simpleXmlElement->authenticationSuccess->user
        );
    }

    /**
     * @param  string                             $version
     * @return Cas
     * @throws Adapter\Exception\InvalidArgumentException
     */
    public function setProtocolVersion($version)
    {
        $knownVersions = array(
            self::CAS_1_0,
            self::CAS_2_0,
        );

        if (!in_array($version, $knownVersions)) {
            throw new Adapter\Exception\InvalidArgumentException(
                sprintf(
                    'Protocol version %s not supported.',
                    $version
                )
            );
        }

        $this->protocolVersion = $version;

        return $this;
    }

    /**
     * @param  string $uri
     * @return Cas
     */
    public function setServerUri($uri)
    {
        $this->serverUri = rtrim($uri, '/');

        return $this;
    }

    /**
     * @param  array                $parameters
     * @return Authentication\Result
     */
    public function validate(array $parameters)
    {
        try {
            $uri = $this->createValidateUri($parameters);
        } catch (Adapter\Exception\InvalidArgumentException $e) {
            return new Authentication\Result(
                Authentication\Result::FAILURE,
                '',
                array($e->getMessage())
            );
        }

        $this->httpClient->resetParameters();
        $this->httpClient->setUri($uri);

        try {
            $response = $this->httpClient->send();
        } catch (Http\Exception\RuntimeException $e) {
            return new Authentication\Result(
                Authentication\Result::FAILURE_UNCATEGORIZED,
                '',
                array(
                    $e->getMessage()
                )
            );
        }

        if (!$response->isSuccess()) {
            return new Authentication\Result(
                Authentication\Result::FAILURE_UNCATEGORIZED,
                '',
                array(
                    'HTTP response did not indicate success.'
                )
            );
        }

        $body = $response->getBody();

        $explodedResponse = explode("\n", $body);

        if (count($explodedResponse) < 2) {
            return new Authentication\Result(
                Authentication\Result::FAILURE_UNCATEGORIZED,
                '',
                array(
                    'Got an invalid CAS 1.0 response.'
                )
            );
        }

        $status = $explodedResponse[0];
        $identity = $explodedResponse[1];

        if ($status !== 'yes') {
            return new Authentication\Result(
                Authentication\Result::FAILURE_UNCATEGORIZED,
                '',
                array(
                    'Authentication failed.'
                )
            );
        }

        return new Authentication\Result(
            Authentication\Result::SUCCESS,
            $identity
        );
    }

    protected function createUri(
        $endpoint,
        array $requiredParameters,
        array $parameters
    ) {
        $this->ensureRequiredParametersExist(
            $requiredParameters,
            $parameters
        );

        $uri = $this->getServerUri() . "/{$endpoint}";

        $query = http_build_query($parameters);

        if (!empty($query)) {
            $uri .= '?' . $query;
        }

        return $uri;
    }

    protected function ensureRequiredParametersExist(
        array $requiredParameters,
        array $parameters
    ) {
        foreach ($requiredParameters as $parameter) {
            if (!array_key_exists($parameter, $parameters)) {
                throw new Adapter\Exception\InvalidArgumentException(
                    sprintf(
                        '"%s" is a required parameter but was not given.',
                        $parameter
                    )
                );
            }
        }
    }
}
