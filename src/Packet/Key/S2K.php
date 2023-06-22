<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Common\S2K as BaseS2K;
use OpenPGP\Enum\{
    HashAlgorithm,
    S2kType,
};

/**
 * String-to-key class
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class S2K extends BaseS2K
{
}
