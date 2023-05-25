<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Message;

use DateTime;
use OpenPGP\Key\PrivateKey;
use OpenPGP\Packet\LiteralData;
use OpenPGP\Packet\Signature as SignaturePacket;
use OpenPGP\Type\{
    CleartextMessagenterface,
    MessageInterface,
    SignatureInterface,
    SignedMessageInterface,
};

/**
 * Cleartext message class
 *
 * @package   OpenPGP
 * @category  Message
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class CleartextMessage implements CleartextMessagenterface
{
    /**
     * Constructor
     *
     * @param string $text
     * @return self
     */
    public function __construct(
        private readonly string $text
    )
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getText(): string
    {
        return rtrim($this->text);
    }

    /**
     * {@inheritdoc}
     */
    public function getNormalizeText(): string
    {
        return preg_replace('/\r\n/m', "\n", rtrim($this->text));
    }

    /**
     * {@inheritdoc}
     */
    public function sign(
        array $signingKeys, ?DateTime $time = null
    ): SignedMessageInterface
    {
        return new SignedMessage(
            $this->getText(), $this->signDetached($signingKeys, $time)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function signDetached(
        array $signingKeys, ?DateTime $time = null
    ): SignatureInterface
    {
        $signingKeys = array_filter(
            $signingKeys, static fn ($key) => $key instanceof PrivateKey
        );
        if (empty($signingKeys)) {
            throw new \InvalidArgumentException('No signing keys provided');
        }
        $packets = array_map(
            fn ($key) => SignaturePacket::createLiteralData(
                $key->getSigningKeyPacket(),
                LiteralData::fromText($this->getText()),
                $time
            ),
            $signingKeys
        );
        return new Signature($packets);
    }

    /**
     * {@inheritdoc}
     */
    public function verifyDetached(
        array $verificationKeys, SignatureInterface $signature, ?DateTime $time = null
    ): array
    {
        return $signature->verifyCleartext(
            $verificationKeys, $this, $time
        );
    }
}
