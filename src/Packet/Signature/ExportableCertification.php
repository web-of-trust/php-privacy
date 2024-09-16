<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Signature;

use OpenPGP\Enum\SignatureSubpacketType;
use OpenPGP\Packet\SignatureSubpacket;

/**
 * Exportable certification sub-packet class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class ExportableCertification extends SignatureSubpacket
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
            SignatureSubpacketType::ExportableCertification->value,
            $data,
            $critical,
            $isLong
        );
    }

    /**
     * From exportable
     *
     * @param bool $exportable
     * @param bool $critical
     * @return self
     */
    public static function fromExportable(
        bool $exportable = true, bool $critical = false
    ): self
    {
        return new self(
            $exportable ? "\x01" : "\x00", $critical
        );
    }
}
