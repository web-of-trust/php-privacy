<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Signature;

use OpenPGP\Enum\{
    SignatureSubpacketType,
    SupportFeature,
};
use OpenPGP\Packet\SignatureSubpacket;

/**
 * Features sub-packet class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class Features extends SignatureSubpacket
{
    /**
     * Constructor
     *
     * @param string $data
     * @param bool $critical
     * @param bool $isLong
     * @return self
     */
    public function __construct(
        string $data,
        bool $critical = false,
        bool $isLong = false
    )
    {
        parent::__construct(
            SignatureSubpacketType::Features->value,
            $data,
            $critical,
            $isLong
        );
    }

    /**
     * From features
     *
     * @param int $features
     * @param bool $critical
     * @return self
     */
    public static function fromFeatures(
        int $features = 0, bool $critical = false
    ): self
    {
        return new self(chr($features), $critical);
    }

    /**
     * Support version 1 SEIPD
     *
     * @return bool
     */
    public function supportVersion1SEIPD(): bool
    {
        return (ord($this->getData()[0]) & SupportFeature::Version1SEIPD->value)
            === SupportFeature::Version1SEIPD->value;
    }

    /**
     * Support version 2 SEIPD
     *
     * @return bool
     */
    public function supportVersion2SEIPD(): bool
    {
        return (ord($this->getData()[0]) & SupportFeature::Version2SEIPD->value)
            === SupportFeature::Version2SEIPD->value;
    }
}
