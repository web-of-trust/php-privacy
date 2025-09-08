<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Message;

use DateTimeInterface;
use OpenPGP\Common\Helper;
use OpenPGP\Packet\{LiteralData, PacketList};
use OpenPGP\Packet\Signature as SignaturePacket;
use OpenPGP\Type\{
    CleartextMessageInterface,
    NotationDataInterface,
    PrivateKeyInterface,
    SignatureInterface,
    SignedMessageInterface,
};

/**
 * Cleartext message class
 *
 * Class that represents an OpenPGP cleartext message.
 *
 * See RFC 9580, section 7.
 *
 * @package  OpenPGP
 * @category Message
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class CleartextMessage implements CleartextMessageInterface
{
    /**
     * Constructor
     *
     * @param string $text
     * @return self
     */
    public function __construct(private readonly string $text) {}

    /**
     * {@inheritdoc}
     */
    public function getText(): string
    {
        return $this->text;
    }

    /**
     * {@inheritdoc}
     */
    public function getNormalizeText(): string
    {
        // Remove trailing whitespace and
        // normalize EOL to canonical form <CR><LF>
        $text = Helper::removeTrailingSpaces($this->text);
        return preg_replace(Helper::EOL_PATTERN, Helper::CRLF, $text) ?? $text;
    }

    /**
     * {@inheritdoc}
     */
    public function sign(
        array $signingKeys,
        array $recipients = [],
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null,
    ): SignedMessageInterface {
        return new SignedMessage(
            $this->getText(),
            $this->signDetached(
                $signingKeys,
                $recipients,
                $notationData,
                $time,
            ),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function signDetached(
        array $signingKeys,
        array $recipients = [],
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null,
    ): SignatureInterface {
        $signingKeys = array_filter(
            $signingKeys,
            static fn($key) => $key instanceof PrivateKeyInterface,
        );
        if (empty($signingKeys)) {
            throw new \InvalidArgumentException("No signing keys provided.");
        }
        return new Signature(
            new PacketList(
                array_map(
                    fn($key) => SignaturePacket::createLiteralData(
                        $key->getSecretKeyPacket(),
                        LiteralData::fromText($this->getText()),
                        $recipients,
                        $notationData,
                        $time,
                    ),
                    $signingKeys,
                ),
            ),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function verifyDetached(
        array $verificationKeys,
        SignatureInterface $signature,
        ?DateTimeInterface $time = null,
    ): array {
        return $signature->verifyCleartext($verificationKeys, $this, $time);
    }
}
