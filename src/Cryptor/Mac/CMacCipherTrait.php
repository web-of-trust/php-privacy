<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Cryptor\Mac;

/**
 * CMac cipher trait
 * 
 * @package  OpenPGP
 * @category Cryptor
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
trait CMacCipherTrait
{
    /**
     * Constructor
     *
     * @return self
     */
    public function __construct() {
        parent::__construct('cbc');
        $this->setPreferredEngine('PHP');
    }

    /**
     * {@inheritdoc}
     */
    public function encryptBlock($in) {
        $this->setup();
        return parent::encryptBlock($in);
    }
}
