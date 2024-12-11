<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Signature;

use OpenPGP\Enum\{AeadAlgorithm, SignatureSubpacketType, SymmetricAlgorithm};
use OpenPGP\Packet\SignatureSubpacket;
use phpseclib3\Common\Functions\Strings;

/**
 * PreferredAeadCiphers sub-packet class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class PreferredAeadCiphers extends SignatureSubpacket
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
    ) {
        parent::__construct(
            SignatureSubpacketType::PreferredAeadCiphers->value,
            $data,
            $critical,
            $isLong
        );
    }

    /**
     * Get preferred aeads by given symmetric
     *
     * @param SymmetricAlgorithm $symmetric
     * @return array
     */
    public function getPreferredAeads(SymmetricAlgorithm $symmetric): array
    {
        $aeads = [];
        $data = $this->getData();
        while (strlen($data) > 0) {
            $ciphers = str_split(Strings::shift($data, 2));
            if (count($ciphers) == 2) {
                $preferred = SymmetricAlgorithm::from(ord($ciphers[0]));
                if ($symmetric == $preferred) {
                    $aeads[] = AeadAlgorithm::from(ord($ciphers[1]));
                }
            }
        }

        return $aeads;
    }
}
