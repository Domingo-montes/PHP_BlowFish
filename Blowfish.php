<?php
/**
 * Crypto_Blowfish allows encryption/decryption on the fly using
 * the Blowfish algorithm. Crypto_Blowfish discart the mcrypt
 * PHP extension, it uses only PHP.
 * Crypt_Blowfish support encryption/decryption with or without a secret key.
 *
 * Tailored to work in PHP version 7 by Domingo A. Montes
 * Based on the original Crypt_Blowfish of Matthew Fonda <mfonda@php.net>
 *
 * Return Bin result
 * @category   Encryption
 * @package    Crypto_Blowfish
 * @author     
 * @copyright  2005 Matthew Fonda
 * @version    Blowfish.php,v 1.0.0 2022/06/27 
 * @link       http://pear.php.net/package/Crypto_Blowfish
 */

require_once 'PEAR.php';

/**
 *
 * Example usage:
 * $bf = new Crypto_Blowfish('some secret key!');
 * $encrypted = $bf->encrypt('this is some example plain text');
 * $plaintext = $bf->decrypt($encrypted);
 * echo "plain text: $plaintext";
 *
 * @category   Encryption
 * @package    Crypto_Blowfish
 * @author     Domingo A. Montes
 * @copyright  n/a
 * @link       http://pear.php.net/package/Crypto_Blowfish
 * @version    1.0.0
 * @access     public
 */
class Crypto_Blowfish{

    /**
     * P-Array contains 18 32-bit subkeys, used for Permutation
     *
     * @var array
     * @access private
     */
    var $_P = [];
        
    /**
     * Array of four S-Blocks each containing 256 32-bit entries, used for Substitution
     *
     * @var array
     * @access private
     */
    var $_S = [];

    /**
     * Mcrypt td resource
     *
     * @var resource
     * @access private
     */
    var $_td = null;

    /**
     * Initialization vector
     *
     * @var string
     * @access private
     */
    var $_iv = null;
    
    /**
     * Crypt_Blowfish Constructor
     * Initializes the Crypt_Blowfish object, and gives a sets
     * the secret key
     *
     * @param string $key
     * @access public
     */
    function Crypt_Blowfish($key){
    
        $this->setKey($key);
    }
    
    /**
     * Deprecated isReady method
     *
     * @return bool
     * @access public
     * @deprecated
     */
    function isReady(){
    	return true;
    }
    
    /**
     * Initializes the Crypt_Blowfish object
     *
     * @access private
     */
    function _init(){
    	$defaults = new Crypto_Blowfish_DefaultKey();
		$this->_P = $defaults->P;
        $this->_S = $defaults->S;
    }
            
    /**
     * Enciphers a single 64 bit block
     *
     * @param int &$Xl
     * @param int &$Xr
     * @access private
     */
    function _encipher(&$Xl, &$Xr){
    	for ($i = 0; $i < 16; $i++) {
            $temp = $Xl ^ $this->_P[$i];
            $Xl = ((($this->_S[0][($temp>>24) & 255] +
                            $this->_S[1][($temp>>16) & 255]) ^
                            $this->_S[2][($temp>>8) & 255]) +
                            $this->_S[3][$temp & 255]) ^ $Xr;
            $Xr = $temp;
        }
        $Xr = $Xl ^ $this->_P[16];
        $Xl = $temp ^ $this->_P[17];
    }
      
    /**
     * Deciphers a single 64 bit block
     *
     * @param int &$Xl
     * @param int &$Xr
     * @access private
     */
    function _decipher(&$Xl, &$Xr){
    	for ($i = 17; $i > 1; $i--) {
            $temp = $Xl ^ $this->_P[$i];
            $Xl = ((($this->_S[0][($temp>>24) & 255] +
                            $this->_S[1][($temp>>16) & 255]) ^
                            $this->_S[2][($temp>>8) & 255]) +
                            $this->_S[3][$temp & 255]) ^ $Xr;
            $Xr = $temp;
        }
        $Xr = $Xl ^ $this->_P[1];
        $Xl = $temp ^ $this->_P[0];
    }
    
     /**
     * Encrypts a string
     *
     * @param string $plainText
     * @return string Returns cipher text on success, PEAR_Error on failure
     * @access public
     */
    function encrypt($plainText){
    
        if (!is_string($plainText)) {
            PEAR::raiseError('Plain text must be a string', 0, PEAR_ERROR_DIE);
        }
		$this->_init();
   
        $cipherText = '';
        $len = strlen($plainText);
        $plainText .= str_repeat(chr(0),(8 - ($len%8))%8);
        for ($i = 0; $i < $len; $i += 8) {
            list(,$Xl,$Xr) = unpack("N2",substr($plainText,$i,8));
            $this->_encipher($Xl, $Xr);
            $cipherText .= pack("N2", $Xl, $Xr);
        }
        return $cipherText;
    }
        
    /**
     * Decrypts an encrypted string
     *
     * @param string $cipherText
     * @return string Returns plain text on success, PEAR_Error on failure
     * @access public
     */
    function decrypt($cipherText){
    
        if (!is_string($cipherText)) {
            PEAR::raiseError('Chiper text must be a string', 1, PEAR_ERROR_DIE);
        }
		$this->_init();

        $plainText = '';
        $len = strlen($cipherText);
        $cipherText .= str_repeat(chr(0),(8 - ($len%8))%8);
        for ($i = 0; $i < $len; $i += 8) {
            list(,$Xl,$Xr) = unpack("N2",substr($cipherText,$i,8));
            $this->_decipher($Xl, $Xr);
            $plainText .= pack("N2", $Xl, $Xr);
        }
        return $plainText;
    }
       
    /**
     * Sets the secret key
     * The key must be non-zero, and less than or equal to
     * 56 characters in length.
     *
     * @param string $key
     * @return bool  Returns true on success, PEAR_Error on failure
     * @access public
     */
    function setKey($key){
    
        if (!is_string($key)) {
            PEAR::raiseError('Key must be a string', 2, PEAR_ERROR_DIE);
        }

        $len = strlen($key);

        if ($len > 56 || $len == 0) {
            PEAR::raiseError('Key must be < 56 characters and !0. Supplied key length: ' . $len, 3, PEAR_ERROR_DIE);
        }

        require_once './DefaultKey.php';
        $this->_init();
        
        $k = 0;
        $data = 0;
        $datal = 0;
        $datar = 0;
        
        for ($i = 0; $i < 18; $i++) {
            $data = 0;
            for ($j = 4; $j > 0; $j--) {
				$data = $data << 8 | ord($key[$k]);
				$k = ($k+1) % $len;
            }
            $this->_P[$i] ^= $data;
        }
        
        for ($i = 0; $i <= 16; $i += 2) {
            $this->_encipher($datal, $datar);
            $this->_P[$i] = $datal;
            $this->_P[$i+1] = $datar;
        }
        for ($i = 0; $i < 256; $i += 2) {
            $this->_encipher($datal, $datar);
            $this->_S[0][$i] = $datal;
            $this->_S[0][$i+1] = $datar;
        }
        for ($i = 0; $i < 256; $i += 2) {
            $this->_encipher($datal, $datar);
            $this->_S[1][$i] = $datal;
            $this->_S[1][$i+1] = $datar;
        }
        for ($i = 0; $i < 256; $i += 2) {
            $this->_encipher($datal, $datar);
            $this->_S[2][$i] = $datal;
            $this->_S[2][$i+1] = $datar;
        }
        for ($i = 0; $i < 256; $i += 2) {
            $this->_encipher($datal, $datar);
            $this->_S[3][$i] = $datal;
            $this->_S[3][$i+1] = $datar;
        }
        
        return true;
    }   
}
?>