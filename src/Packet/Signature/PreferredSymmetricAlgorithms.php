<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Signature;

use OpenPGP\Enum\{SignatureSubpacketType, SymmetricAlgorithm};
use OpenPGP\Packet\SignatureSubpacket;

/**
 * PreferredSymmetricAlgorithms sub-packet class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class PreferredSymmetricAlgorithms extends SignatureSubpacket
{
    /**
     * Constructor
     *
     * @param string $data
     * @param bool $critical
     * @return self
     */
    public function __construct(string $data, bool $critical = false)
    {
        parent::__construct(
            SignatureSubpacketType::PreferredSymmetricAlgorithms->value,
            $data,
            $critical,
        );
    }

    /**
     * Get preferences
     *
     * @return array
     */
    public function getPreferences(): array
    {
        return array_map(
            static fn($pref) => SymmetricAlgorithm::from(ord($pref)),
            str_split($this->getData()),
        );
    }
}
