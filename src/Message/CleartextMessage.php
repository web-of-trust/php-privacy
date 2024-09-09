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
use OpenPGP\Packet\{
    LiteralData,
    PacketList,
};
use OpenPGP\Packet\Signature as SignaturePacket;
use OpenPGP\Type\{
    CleartextMessageInterface,
    MessageInterface,
    NotationDataInterface,
    PrivateKeyInterface,
    SignatureInterface,
    SignedMessageInterface,
};

/**
 * Cleartext message class
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
        $text = Helper::removeTrailingSpaces($this->text);
        return preg_replace(
            '/\r?\n/m', "\r\n", $text
        ) ?? $text;
    }

    /**
     * {@inheritdoc}
     */
    public function getNormalizeText(): string
    {
        return preg_replace('/\r\n/m', "\n", $this->getText());
    }

    /**
     * {@inheritdoc}
     */
    public function sign(
        array $signingKeys,
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null
    ): SignedMessageInterface
    {
        return new SignedMessage(
            $this->getText(), $this->createSignature(
                $signingKeys,
                false,
                $notationData,
                $time
            )
        );
    }

    /**
     * {@inheritdoc}
     */
    public function signDetached(
        array $signingKeys,
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null
    ): SignatureInterface
    {
        return $this->createSignature(
            $signingKeys,
            true,
            $notationData,
            $time
        );
    }

    /**
     * {@inheritdoc}
     */
    public function verifyDetached(
        array $verificationKeys,
        SignatureInterface $signature,
        ?DateTimeInterface $time = null
    ): array
    {
        return $signature->verifyCleartext(
            $verificationKeys, $this, true, $time
        );
    }

    /**
     * Create literal signature.
     *
     * @param array $signingKeys
     * @param bool $detached
     * @param NotationDataInterface $notationData
     * @param DateTimeInterface $time
     * @return SignatureInterface
     */
    private function createSignature(
        array $signingKeys,
        bool $detached = false,
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null,
    ): SignatureInterface
    {
        $signingKeys = array_filter(
            $signingKeys,
            static fn ($key) => $key instanceof PrivateKeyInterface
        );
        if (empty($signingKeys)) {
            throw new \InvalidArgumentException(
                'No signing keys provided.'
            );
        }
        $packets = array_map(
            fn ($key) => SignaturePacket::createLiteralData(
                $key->getSigningKeyPacket(),
                LiteralData::fromText($this->getText()),
                $detached,
                $notationData,
                $time
            ),
            $signingKeys
        );
        return new Signature(new PacketList($packets));
    }
}
