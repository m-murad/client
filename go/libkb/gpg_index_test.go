// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package libkb

import (
	"bytes"
	"strings"
	"testing"
)

func parse(t *testing.T, kr string) *GpgKeyIndex {
	buf := bytes.NewBufferString(kr)
	i, w, e := ParseGpgIndexStream(buf)
	if e != nil {
		t.Fatalf("failure in parse: %s", e)
	}

	if !w.IsEmpty() {
		t.Errorf("Warnings in parsing:")
		w.Warn()
		return nil
	}
	return i
}

func TestParseMyKeyring(t *testing.T) {
	parse(t, myKeyring)
}

func TestFindMax(t *testing.T) {
	index := parse(t, myKeyring)
	keylist := index.Emails.Get("themax@gmail.com")
	if keylist == nil {
		t.Errorf("nil keylist was not expected")
	} else if len(keylist) != 2 {
		t.Errorf("expected two keys for max")
	} else {
		expected := map[string]bool{
			"8EFBE2E4DD56B35273634E8F6052B2AD31A6631C": true,
			"4475293306243408FA5958DC63847B4B83930F0C": true,
		}
		for _, k := range keylist {
			if fp := k.GetFingerprint(); fp == nil {
				t.Errorf("Unexpected empty fingerprint")
			} else if ok, found := expected[strings.ToUpper(fp.String())]; !ok || !found {
				t.Errorf("Unexpected fingerprint: %s", fp.String())
			}
		}
	}
}

func TestYubikeySecretKeys(t *testing.T) {
	index := parse(t, yubikey4)
	keylist := index.Emails.Get("dain@yubico.com")
	if keylist == nil {
		t.Errorf("nil keylist was not expected")
	} else if len(keylist) != 1 {
		t.Errorf("expected two keys for max")
	}
}

const myKeyring = `
tru::1:1416474053:1439900531:3:1:5
pub:u:2048:17:76D78F0500D026C4:1282220531:1439900531::u:::scESC:
fpr:::::::::85E38F69046B44C1EC9FB07B76D78F0500D026C4:
uid:u::::1344775710::CAACC8CE9116A0BE42E58C61602F127B194EF5A5::GPGTools Team <team@gpgtools.org>:
uid:u::::1282220531::03B2DCE7652DBBB93DA77FFC4328F122656E20DD::GPGMail Project Team (Official OpenPGP Key) <gpgmail-devel@lists.gpgmail.org>:
uid:u::::1344775710::8CACAFAD028BE38151D2361F9CD79CC81B4153B2::GPGTools Project Team (Official OpenPGP Key) <gpgtools-org@lists.gpgtools.org>:
uat:u::::1321476238::076E59FC200B10E38AEEA745AB6547AEE99FB9EE::1 5890:
sub:u:2048:16:07EAE49ADBCBE671:1282220531:1439900531:::::e:
fpr:::::::::CF5DA29DD13D6856B5820B2F07EAE49ADBCBE671:
sub:u:4096:1:E8A664480D9E43F5:1396950003:1704188403:::::s:
fpr:::::::::8C31E5A17DD5D932B448FE1DE8A664480D9E43F5:
pub:u:4096:1:FBC07D6A97016CB3:1381159886:1507390286::u:::escaESCA:
fpr:::::::::94AA3A5BDBD40EA549CABAF9FBC07D6A97016CB3:
uid:u::::1415222273::323D79D8863BA8F45C43217AA3197816DB1D6C82::Chris Coyne <chris@okcupid.com>:
uid:u::::1381159886::CF5361B3D400B377CED49FD557B744E93FA344D4::Chris Coyne <chris@chriscoyne.com>:
uid:u::::1415222233::4690BE55B82498795187834A5B960515BAE36113::Chris Coyne <ccoyne77@gmail.com>:
uid:u::::1381159886::9DFEAB6033B858FD7A80C11E5E31EA709573D7E9::keybase.io/chris <chris@keybase.io>:
sub:u:4096:1:D224413B1CFA6490:1381159886:1507390286:::::esa:
fpr:::::::::803634EFEB38F9370F9C58ABD224413B1CFA6490:
pub:-:4096:1:4F04069FE2052317:1392417704:1707777704::-:::escaESCA:
fpr:::::::::419877544E88410632624ACB4F04069FE2052317:
uid:-::::1392417704::D2D2A2969DF6DC0B947CE9D17CC356EBE3822937::keybase.io/aston <aston@keybase.io>:
sub:-:4096:1:C502FF1549ABE8E7:1392417704:1707777704:::::esa:
fpr:::::::::12D125686EE1310D8C3219F9C502FF1549ABE8E7:
pub:u:4096:1:47484E50656D16C7:1384876967:1511107367::u:::scESC:
fpr:::::::::222B85B0F90BE2D24CFEB93F47484E50656D16C7:
uid:u::::1384876967::5379B9706C5D468C86A572B07E28EBDB26BE0E97::Keybase.io Code Signing (v1) <code@keybase.io>:
sub:u:4096:1:5929664098F03378:1384876967:1511107367:::::e:
fpr:::::::::10F79F9BEB724B73FB673D385929664098F03378:
pub:u:4096:1:63847B4B83930F0C:1380929487:1507159887::u:::escaESCA:
fpr:::::::::4475293306243408FA5958DC63847B4B83930F0C:
uid:u::::1387217771::759D5C7C38AD60551D46D2E6F34BA03640FE4379::Maxwell Krohn <themax@gmail.com>:
uid:u::::1380929487::14BC0C35326061518657E0B8F71A23E0CA537034::Max Krohn <themax@gmail.com>:
sub:u:4096:1:2FE01C454348DA39:1380929487:1507159887:::::esa:
fpr:::::::::C4EE7BCBCE2F0953DCF9E8902FE01C454348DA39:
pub:u:2048:1:2EE0695E30C55BEF:1392816673:1708176673::u:::scESC:
fpr:::::::::F1DEFAA6B3DB297FB824CB512EE0695E30C55BEF:
uid:u::::1392816673::082E8013E42FE9646212330D7931B969029485CE::Max Test (test) <themax+1@gmail.com>:
sub:u:2048:1:091E2177A50BA645:1392816673:1708176673:::::e:
fpr:::::::::B80B0A78852880A93FE421BD091E2177A50BA645:
pub:-:4096:1:EBF01804BCF05F6B:1346326188:::-:::escaESCA:
fpr:::::::::428DF5D63EF07494BB455AC0EBF01804BCF05F6B:
uid:-::::1388587863::2D64E83198C753709219CA0FDF17A2A48D994366::Filippo Valsorda <fv@filippo.io>:
uid:-::::1388587850::ED4AFBC98FD3B49AE8CA7733A27BE82FFFB5E53F::Filippo Valsorda <filippo.valsorda@gmail.com>:
uid:-::::1360528876::788372CBC7DDF24564AEA7138ABB09A648499E32::Filippo Valsorda <filosottile.wiki@gmail.com>:
sub:e:2048:1:50223425F149AA25:1360529005:1392065005:::::s:
fpr:::::::::2D098FADCE5B408F1C77F8E750223425F149AA25:
sub:e:2048:1:3D1C752C0D83D9EC:1360529191:1392065191:::::e:
fpr:::::::::40D449F18A85797C8E1770B43D1C752C0D83D9EC:
sub:-:2048:1:204D8240101F5216:1388587898:1420123898:::::s:
fpr:::::::::ED2914BDFDDBB162C77A9F80204D8240101F5216:
sub:-:2048:1:262B4EF067BA72AF:1388588025:1420124025:::::e:
fpr:::::::::72F48FF302283C9FA3CFD5B5262B4EF067BA72AF:
pub:u:1024:17:910A9D8D1792F55B:1392902586:1708262586::u:::scESC:
fpr:::::::::37D30E298D0045FDDD506346910A9D8D1792F55B:
uid:u::::1392902586::AD6E6A9DA7A2A867CA8867393464E0D439ECFDDE::Max Planck (password is 'mmpp') <planck@berlin.ac.de>:
uid:u::::1392902586::14EBD18210821757B348F0974CE9AC8AEAFF97BA::keybase.io/max2 <max2@keybase.io>:
sub:u:1024:16:A1910E8DC491E958:1392902586:1708262586:::::e:
fpr:::::::::0C0A78ECB880319EBE801C87A1910E8DC491E958:
pub:u:2048:1:D2CBE4585360C01C:1392926252:1708286252::u:::scESC:
fpr:::::::::1DBC14CFDCA08845CEF8D56ED2CBE4585360C01C:
uid:u::::1392926252::56C755C67184046B404B3343B144A4D7B642A894::Herb Kitch (Test Key) <herb.ketch@gov.uk>:
sub:u:2048:1:2C95AFC9FDC426E5:1392926252:1708286252:::::e:
fpr:::::::::D604AFB62A06807B7FB124B52C95AFC9FDC426E5:
pub:u:4096:1:919305DF414C79F6:1393194839:1708554839::u:::scESC:
fpr:::::::::D53D874FEB31616F51D81069919305DF414C79F6:
uid:u::::1393194839::1D5AA43907416362F096D2D34AEE8F1805576124::Keybase Backup (v1) <backup@keybase.io>:
sub:u:4096:1:250D3F1E2F22B529:1393194839:1708554839:::::e:
fpr:::::::::6C397E3C502192933DD0C144250D3F1E2F22B529:
pub:u:4096:1:E26A29910D2470BE:1392486098:1707846098::u:::escaESCA:
fpr:::::::::C136F24BFB6CCA288158B576E26A29910D2470BE:
uid:u::::1392486098::C973E2B56D13F1CF8C4A57076C046672ADFDE145::keybase.io/wdaher (v0.0.1) <wdaher@keybase.io>:
sub:u:2048:1:F703B25389906F33:1392486098:1424022098:::::esa:
fpr:::::::::4580569CD7D98B4643404568F703B25389906F33:
pub:-:8192:1:0DAA1A4AB1D88291:1392437545:1613189545::-:::scESC:
fpr:::::::::5E685E60EB8733654DCB00570DAA1A4AB1D88291:
uid:-::::1392438504::A6B93F697800D36A086BC778081AC77B239BB065::Sidney San Martín (Born 1989-7-1 in San Francisco, CA):
uid:-::::1392438141::988DE166E3890A7DDDACCFD2D5350A7149E5078B::Sidney San Martín <sidney@okcupid.com>:
uid:-::::1392438106::3F8A606B1389583AB0FE77059ACA0251BBBB5B3B::Sidney San Martín <sidney@s4y.us>:
sub:-:8192:1:2831A2BE59FEA86F:1392437545:1613189545:::::e:
fpr:::::::::3DD85340C60CB3173AB8579B2831A2BE59FEA86F:
pub:-:4096:1:288EDB4733616035:1390306245:1705666245::-:::scESC:
fpr:::::::::B658B173C61EA483C0D01E9D288EDB4733616035:
uid:-::::1391052728::E5E8323D8182BB40FDB129D625AF30DC6F2B62C4::Andrew Gwozdziewycz <apg@sigusr2.net>:
uid:-::::1390306245::8A39C264E3F6DE6A226406D92FA23C6ABF5BE20C::Andrew Gwozdziewycz <me@apgwoz.com>:
uid:-::::1391052536::C8A26F3904DC08993B6F4D116CAE27C06917E539::Andrew Gwozdziewycz <web@apgwoz.com>:
uid:-::::1391052673::1D0B55B327BE733076BCACD1454B80DA9146AD85::Andrew Gwozdziewycz <git@apgwoz.com>:
uid:-::::1391052696::730D53519F1910B97CA9E867B7DD8F3EEF64A1FD::Andrew Gwozdziewycz <apgwoz@gmail.com>:
sub:-:4096:1:989275C75347F303:1390306245:1705666245:::::e:
fpr:::::::::AFA3F945A6D05343AD283F32989275C75347F303:
pub:-:4096:1:D28390C6F7CDD0BA:1393259803:1708619803::-:::escaESCA:
fpr:::::::::F544F89FB9AFC481DCB26730D28390C6F7CDD0BA:
uid:-::::1393259803::2249EEC3751364F2E3BB0CAFD34A6C9785A9AD26::keybase.io/max1 <max1@keybase.io>:
sub:-:4096:1:FE968337A60DA0A4:1393259803:1708619803:::::esa:
fpr:::::::::A9929FBBE9AE7EF674346449FE968337A60DA0A4:
pub:-:1024:17:AC859362B0413BFA:943674453:::-:::scESC:
fpr:::::::::DE47BC9E6D2DA6B02DC610B1AC859362B0413BFA:
uid:-::::1377018882::38128A333FFB8FA1D4387F9F3C65A2D2FEE2D1C1::Gregory Maxwell <greg@xiph.org>:
uid:-::::1377018880::5415DACFD5BBC93B9C86389B3521A7E15C9CC7DE::Gregory Maxwell <gmaxwell@gmail.com>:
uid:r::::::91723BCF5FAF8940D24572242529D7F9F74CC688::Gregory Maxwell <gmaxwell@juniper.net>:
uid:r::::::A4248851EFC00E1A833E10262FC7F8250F314CCD::Gregory Maxwell <greg@linuxpower.cx>:
uid:r::::::C387E59FC7500938AC6CCAEB03A87F107CCAEB57::Gregory Maxwell <gmaxwell@martin.fl.us>:
uat:-::::1142671127::C020317D61C27D09BC7409382714F5EA4B0B9A7F::1 6038:
uid:-::::1174738550::3F9A302C8FB31B0D49E87503D6353EAB1E9454C8::Gregory Maxwell <gmaxwell@wikimedia.org>:
uid:-::::1360375343::DCD6D818D89EFBD7FA7D1004EE9954FAB6EE14EC::Gregory Maxwell <gmaxwell@mozilla.com>:
sub:r:2048:16:3261CC7DF0F0B355:943674503::::::e:
fpr:::::::::CCE142FB2426C09B41A60C8C3261CC7DF0F0B355:
sub:-:4096:1:C2A8CB2A253F3FDF:1377018918:1503162918:::::e:
fpr:::::::::20595CB8560782DF302CC318C2A8CB2A253F3FDF:
sub:-:4096:1:EAB5AF94D9E9ABE7:1377634098:1535314098:::::s:
fpr:::::::::81291FA67D2C379A006A053FEAB5AF94D9E9ABE7:
pub:u:4096:1:6052B2AD31A6631C:1391639420:1706999420::u:::escaESCA:
fpr:::::::::8EFBE2E4DD56B35273634E8F6052B2AD31A6631C:
uid:u::::1414603912::759D5C7C38AD60551D46D2E6F34BA03640FE4379::Maxwell Krohn <themax@gmail.com>:
uid:u::::1414603912::0E83836893BE1130CC0CCF718A26FA19BCDC5866::keybase.io/max (v0.0.1) <max@keybase.io>:
uid:u::::1394818042::53811772132DAA1EC145F05E27F6298AAA521587::Maxwell Krohn <max@maxk.org>:
uid:u::::1395683671::4994E49FCED0284AF063655ADFDBCB12B4F65745::Maxwell Krohn <krohn@mit.edu>:
uid:u::::1395683700::1AACE33F196DC383CA09DF1485F5086412693E63::Maxwell Krohn <krohn@post.harvard.edu>:
uid:u::::1395683771::EEDD36E49A9440C83645A385F4F9D9FFA3A051D9::Maxwell Krohn <krohn@alum.mit.edu>:
sub:u:2048:1:980A3F0D01FE04DF:1391639420:1423175420:::::esa:
fpr:::::::::4AF88842F72A59565C669BDE980A3F0D01FE04DF:
pub:-:4096:1:EF64151CD1B1B13E:1393625258:1708985258::-:::escaESCA:
fpr:::::::::3F00CA464E081B2204AE7842EF64151CD1B1B13E:
uid:-::::1393625258::3541B4CE1F8EDDAB0A4C04A0C91F01847E183140::keybase.io/paritybit (v0.0.1) <paritybit@keybase.io>:
sub:-:2048:1:2A0688A6E2DC575B:1393625258:1425161258:::::esa:
fpr:::::::::E1D8C791E3A2B91C436051272A0688A6E2DC575B:
`

const yubikey4 = `sec::2048:1:F04367096FBA95E8:1389358404:0::::::::D2760001240102010006042129000000:
fpr:::::::::20EE325B86A81BCBD3E56798F04367096FBA95E8:
uid:::::::CBDD6BD90F5A01A814C4E5A0E05F8D7DC7B3D070::Dain Nilsson <dain@yubico.com>:
ssb::2048:1:BFE3A8E58DB04E9F:1389358404:::::::::D2760001240102010006042129000000:
ssb::2048:1:3B557A2E4C844B75:1389358510:::::::::D2760001240102010006042129000000:
`
