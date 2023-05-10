<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\{HashAlgorithm, KeyAlgorithm, PacketTag, SignatureType};

/**
 * Signature represents a signature.
 * See RFC 4880, section 5.2.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class Signature extends AbstractPacket
{
	private string $signatureData;

    /**
     * Constructor
     *
     * @param int $version
     * @param SignatureType $signatureType
     * @param KeyAlgorithm $keyAlgorithm
     * @param HashAlgorithm $hashAlgorithm
     * @param string $signedHashValue
     * @param string $signature
     * @param array $hashedSubpackets
     * @param array $unhashedSubpackets
     * @return self
     */
    public function __construct(
    	private int $version,
    	private SignatureType $signatureType,
    	private KeyAlgorithm $keyAlgorithm,
    	private HashAlgorithm $hashAlgorithm,
    	private string $signedHashValue,
    	private string $signature,
    	private array $hashedSubpackets = [],
    	private array $unhashedSubpackets = []
    )
    {
        parent::__construct(PacketTag::Signature);
        $this->hashedSubpackets = array_filter(
            $hashedSubpackets, static fn ($subpacket) => $subpacket instanceof SignatureSubpacket
        );
        $this->unhashedSubpackets = array_filter(
            $unhashedSubpackets, static fn ($subpacket) => $subpacket instanceof SignatureSubpacket
        );
        $this->signatureData = '';
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
        	$this->signatureData,
        	$this->encodeSubpackets($this->unhashedSubpackets),
        	$this->signedHashValue,
        	$this->signature,
        ]);
    }

    private static function encodeSubpackets(array $subpackets): string
    {
        return implode(
            array_map(static fn ($subpacket) => $subpacket->encode(), $subpackets)
        );
    }
}
