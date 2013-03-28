<?php
namespace Tillikum\Authentication;

use Zend\Authentication\Result;

/**
 * Class CasResult
 * Extension of Zend's Authentication\Result class which contains additional information about the Authentication
 * Result.
 */
class CasResult extends Result
{

    /**
     * The contents of the result of the CAS Message
     * @var string
     */
    protected $resultBody;

    /**
     * Sets the result code, identity, and failure messages
     * @param int $code
     * @param mixed $identity
     * @param array $messages
     * @param string|null $resultBody
     */
    public function __construct($code, $identity, array $messages = array(), $resultBody = null)
    {
        parent::__construct($code, $identity, $messages);
        $this->resultBody = $resultBody;
    }


    /**
     * Sets the body of the result message returned from the CAS Server.
     * @param string $resultBody
     */
    public function setResultBody($resultBody)
    {
        $this->resultBody = $resultBody;
    }

    /**
     * Gets the body of the result message returned from the CAS Server.
     * @return string|null
     */
    public function getResultBody()
    {
        return $this->resultBody;
    }

}
