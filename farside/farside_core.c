#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/pci.h>

/*
 * FIXME: Come up with real device ID's, for now use the pci-testdev ID's from
 * QEMU (0x1b36:0005).
 */
#define REDHAT_PCI_VENDOR_ID 0x1b36
#define PCI_VENDOR_ID_FARSIDE REDHAT_PCI_VENDOR_ID
#define PCI_DEVICE_ID_FARSIDE 0x0005

static int farside_probe(struct pci_dev *pdev,
			 const struct pci_device_id *ent)
{
	int ret;

	printk(KERN_ALERT "Probe FARSIDE\n");

	ret = pci_enable_device(pdev);
	if (ret)
		return ret;

	ret = pci_request_regions(pdev, "farside");
	if (ret) {
		dev_err(&pdev->dev, "pci_request_regions() failed.\n");
		goto eenable;
	}

	return 0;

 eenable:
	pci_disable_device(pdev);

	dev_err(&pdev->dev, "FARSIDE initialization failed.\n");

	return ret;
}

static void farside_remove(struct pci_dev *pdev)
{
	printk(KERN_ALERT "Remove FARSIDE\n");

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	return;
}

/*
 * PCI_DEVICE
 */
static const struct pci_device_id farside_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_FARSIDE, PCI_DEVICE_ID_FARSIDE), 0, 0, 0 },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, farside_pci_tbl);

static struct pci_driver farside_pci_driver = {
	.name           = "farside",
	.id_table       = farside_pci_tbl,
	.probe          = farside_probe,
	.remove         = farside_remove,
};

/*
 * FIXME: Cross check whether suffient or whether we need to actually define
 * our own init and exit functions.
 */
module_pci_driver(farside_pci_driver);

MODULE_AUTHOR("Joakim Bech <joakim.bech@linaro.org>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Driver for the FARSIDE chip");
