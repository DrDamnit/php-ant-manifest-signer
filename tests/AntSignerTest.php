<?php

use PHPUnit\Framework\TestCase;

if (!include('includes/PHPAntSigner.class.php')) die ('Could not find PHPAntSigner.class.php');
include('includes/PHPAntSignerFile.class.php');

class PHPAntSignerTest extends TestCase
{
	function testSetApp() {
		$S = new \PHPAnt\Core\PHPAntSigner();
		$result = $S->setApp('ant-app-default');
		$this->assertTrue($result);
		$this->assertSame('ant-app-default', $S->app);
	}

	/**
	 * @depends testSetApp
	 **/

	function testGenerateManifestFile() {
		$S = new \PHPAnt\Core\PHPAntSigner();
		$S->setApp('ant-app-default');
		$S->generateManifestFile();
		$this->assertCount(3, $S->files);

		foreach($S->files as $file) {
			$this->assertInstanceOf('\PHPAnt\Core\PHPAntSignerFile', $file);
		}

		$manifestFilePath = 'includes/apps/ant-app-default/manifest.xml';
		$this->assertFileExists($manifestFilePath);

		$app = simplexml_load_file($manifestFilePath);

		$this->assertSame('DefaultGrammar', (string)$app['name']);
		$this->assertSame('PHPAnt\Apps', (string)$app['namespace']);

		foreach($app->file as $f) {
			$this->assertFileExists((string)$f->name);
		}

		foreach($app->file as $f) {
			$filePath = (string)$f->name;
			$this->assertSame(sha1_file($filePath), (string)$f->hash);
		}
	}

	function testRegisterHook() {
		$hook             = 'cli-init';
		$function         = 'declareMySelf';
		$signature        = $hook.$function.'50';
		$manifestFilePath = 'includes/apps/ant-app-default/manifest.xml';

		$S = new \PHPAnt\Core\PHPAntSigner();
		$S->setApp('ant-app-default');
		$S->registerHook($hook,$function);

		$dom = new \DOMDocument('1.0');
        $dom->load($manifestFilePath);
        $elements = $dom->getElementsByTagName('signature');
        $found = false;

        foreach($elements as $node) {
        	if($node->nodeValue = $signature) {
        		$theNode = $node->parentNode;
        		$found=true;
        	}
        }

        //The node should exist.
		$this->assertTrue($found);

		//Checking to make sure we have cli-init as the hook.
		$hook = $theNode->getElementsByTagName('hook');
		$this->assertSame('cli-init', (string)$hook[0]->nodeValue);

		$hook = $theNode->getElementsByTagName('function');
		$this->assertSame('declareMySelf', (string)$hook[0]->nodeValue);

		$hook = $theNode->getElementsByTagName('priority');
		$this->assertSame('50', (string)$hook[0]->nodeValue);

	}

	function testUnregisterHook() {
		$hook             = 'cli-init';
		$function         = 'declareMySelf';
		$signature        = $hook.$function.'50';
		$manifestFilePath = 'includes/apps/ant-app-default/manifest.xml';

		$S = new \PHPAnt\Core\PHPAntSigner();
		$S->setApp('ant-app-default');

		$dom = new \DOMDocument('1.0');
        $dom->load($manifestFilePath);
        $elements = $dom->getElementsByTagName('signature');
        $found = false;

        foreach($elements as $node) {
        	if($node->nodeValue = $signature) {
        		$theNode = $node->parentNode;
        		$found=true;
        	}
        }

        $this->assertTrue($found);

        $S->removeHook($signature);

        //Remove this node.
		$dom = new \DOMDocument('1.0');
        $dom->load($manifestFilePath);
        $elements = $dom->getElementsByTagName('signature');
		$this->assertEquals(0, $elements->length);
	}

	function testGenKeys() {
		$publicKeyPath  = 'includes/apps/ant-app-default/public.key';
		$privateKeyPath = 'includes/apps/ant-app-default/private.key';
		
		$who = exec('whoami');
		$privateKeyStoragePath = "/home/$who/private.key";


		$S = new \PHPAnt\Core\PHPAntSigner();
		$S->setApp('ant-app-default');
		$S->genKeys();

		copy($privateKeyPath,$privateKeyStoragePath);

		$this->assertFileExists($publicKeyPath);
		$this->assertFileExists($privateKeyPath);
	}

	/**
	 * @depends testGenKeys
	 **/

	function testSignApp() {

		$publicKeyPath         = 'includes/apps/ant-app-default/public.key';
		$manifestFileSignature = 'includes/apps/ant-app-default/manifest.sig';
		$privateKeyFailurePath = 'includes/apps/ant-app-default/private.key';

		//Undo the file we made earlier.
		unlink($privateKeyFailurePath);
		$this->assertFalse(file_exists($privateKeyFailurePath));

		$who = exec('whoami');
		$privateKeyPath = "/home/$who/private.key";
		
		$S = new \PHPAnt\Core\PHPAntSigner();
		$S->setApp('ant-app-default');
		$this->assertFileExists($privateKeyPath);
		$S->signApp($privateKeyPath);

		$this->assertFileExists($manifestFileSignature);

	}
	 /**
	  * @depends testSignApp
	  **/

	function testPrivateKeyMissingException() {
		$publicKeyPath         = 'includes/apps/ant-app-default/public.key';
		$privateKeyFailurePath = 'includes/apps/ant-app-default/private.key';
		$manifestFileSignature = 'includes/apps/ant-app-default/manifest.sig';

		$who = exec('whoami');
		$privateKeyPath = "/home/$who/private.key.wrong";
		
		$S = new \PHPAnt\Core\PHPAntSigner();
		$S->setApp('ant-app-default');

		$this->assertFileExists($manifestFileSignature);

		$this->expectException('Exception');
		$S->signApp($privateKeyPath);
	}

	/**
	 * @depends testPrivateKeyMissingException
	 **/

	function testPrivateKeyInAppException() {
		$publicKeyPath         = 'includes/apps/ant-app-default/public.key';
		$privateKeyFailurePath = 'includes/apps/ant-app-default/private.key';
		$manifestFileSignature = 'includes/apps/ant-app-default/manifest.sig';

		$who = exec('whoami');
		$privateKeyPath = "/home/$who/private.key";
		
		$S = new \PHPAnt\Core\PHPAntSigner();
		$S->setApp('ant-app-default');

		$this->assertFileExists($manifestFileSignature);

		$fh = fopen($privateKeyFailurePath,'w');
		fwrite($fh,'key would go here');
		fclose($fh);

		$this->expectException('Exception');
		$S->signApp($privateKeyPath);
	}
		
	/**
	 * @depends testSignApp
	 **/

	function testVerifyApp() {
		$who = exec('whoami');

		$publicKeyPath  = 'includes/apps/ant-app-default/public.key';
		$privateKeyPath = 'includes/apps/ant-app-default/private.key';
		$privateKeyStoragePath = "/home/$who/private.key";

		$S = new \PHPAnt\Core\PHPAntSigner();
		$S->setApp('ant-app-default');
		$S->genKeys();
		copy($privateKeyPath,$privateKeyStoragePath);
		unlink($privateKeyPath);

		$S->signApp($privateKeyStoragePath);

		$S = new \PHPAnt\Core\PHPAntSigner();
		$S->setApp('ant-app-default');
		$result = $S->verifySignature();		
		$this->assertTrue($result);
	}
}