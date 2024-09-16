<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Message;

use phpseclib3\Common\Functions\Strings;
use OpenPGP\Type\{
    SignaturePacketInterface,
    VerificationInterface,
};

/**
 * Verification class
 *
 * @package  OpenPGP
 * @category Message
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class Verification implements VerificationInterface
{
    /**
     * Constructor
     *
     * @param string $keyID
     * @param SignaturePacketInterface $signaturePacket
     * @param bool $isVerified
     * @param string $verificationError
     * @return self
     */
    public function __construct(
        private readonly string $keyID,
        private readonly SignaturePacketInterface $signaturePacket,
        private readonly bool $isVerified = false,
        private readonly string $verificationError = '',
    )
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyID(bool $toHex = false): string
    {
        return $toHex ? Strings::bin2hex($this->keyID) : $this->keyID;
    }

    /**
     * {@inheritdoc}
     */
    public function getSignaturePacket(): SignaturePacketInterface
    {
        return $this->signaturePacket;
    }

    /**
     * {@inheritdoc}
     */
    public function getVerificationError(): string
    {
        return $this->verificationError;
    }

    /**
     * {@inheritdoc}
     */
    public function isVerified(): bool
    {
        return $this->isVerified;
    }
}
