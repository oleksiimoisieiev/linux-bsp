// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Power Interface (SCMI) Protocol based clock driver
 *
 * Copyright (C) 2021 EPAM.
 */

#include <linux/device.h>
#include <linux/err.h>
#include <linux/of.h>
#include <linux/module.h>
#include <linux/pinctrl/machine.h>
#include <linux/pinctrl/pinconf.h>
#include <linux/pinctrl/pinconf-generic.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/pinmux.h>
#include <linux/scmi_protocol.h>
#include <linux/slab.h>

#include "pinctrl-utils.h"
#include "core.h"
#include "pinconf.h"

#define DRV_NAME "scmi-pinctrl"

struct scmi_pinctrl_funcs {
	unsigned int num_groups;
	const char **groups;
};

struct scmi_pinctrl {
	struct device *dev;
	struct scmi_handle *handle;
	struct pinctrl_dev *pctldev;
	struct pinctrl_desc pctl_desc;
	struct scmi_pinctrl_funcs *functions;
	unsigned int nr_functions;
	char **groups;
	unsigned int nr_groups;
	struct pinctrl_pin_desc *pins;
	unsigned int nr_pins;
};

static int pinctrl_scmi_get_groups_count(struct pinctrl_dev *pctldev)
{
	const struct scmi_handle *handle;
	struct scmi_pinctrl *pmx;

	if (!pctldev)
		return -EINVAL;

	pmx = pinctrl_dev_get_drvdata(pctldev);

	if (!pmx || !pmx->handle)
		return -EINVAL;

	handle = pmx->handle;

	return handle->pinctrl_ops->get_groups_count(handle);
}

static const char *pinctrl_scmi_get_group_name(struct pinctrl_dev *pctldev,
					       unsigned int selector)
{
	int ret;
	const char *name;
	const struct scmi_handle *handle;
	struct scmi_pinctrl *pmx;

	if (!pctldev)
		return NULL;

	pmx = pinctrl_dev_get_drvdata(pctldev);

	if (!pmx || !pmx->handle)
		return NULL;

	handle = pmx->handle;

	ret = handle->pinctrl_ops->get_group_name(handle, selector, &name);
	if (ret) {
		dev_err(pmx->dev, "get name failed with err %d", ret);
		return NULL;
	}

	return name;
}

static int pinctrl_scmi_get_group_pins(struct pinctrl_dev *pctldev,
				       unsigned int selector,
				       const unsigned int **pins,
				       unsigned int *num_pins)
{
	const struct scmi_handle *handle;
	struct scmi_pinctrl *pmx;

	if (!pctldev)
		return -EINVAL;

	pmx = pinctrl_dev_get_drvdata(pctldev);

	if (!pmx || !pmx->handle)
		return -EINVAL;

	handle = pmx->handle;

	return handle->pinctrl_ops->get_group_pins(handle, selector,
						   pins, num_pins);
}

static void pinctrl_scmi_pin_dbg_show(struct pinctrl_dev *pctldev,
				      struct seq_file *s,
				      unsigned int offset)
{
	seq_puts(s, DRV_NAME);
}

#ifdef CONFIG_OF
static int pinctrl_scmi_dt_node_to_map(struct pinctrl_dev *pctldev,
				       struct device_node *np_config,
				       struct pinctrl_map **map,
				       u32 *num_maps)
{
	return pinconf_generic_dt_node_to_map(pctldev, np_config, map,
					      num_maps, PIN_MAP_TYPE_INVALID);
}

static void pinctrl_scmi_dt_free_map(struct pinctrl_dev *pctldev,
				     struct pinctrl_map *map, u32 num_maps)
{
	kfree(map);
}

#endif /* CONFIG_OF */

static const struct pinctrl_ops pinctrl_scmi_pinctrl_ops = {
	.get_groups_count = pinctrl_scmi_get_groups_count,
	.get_group_name = pinctrl_scmi_get_group_name,
	.get_group_pins = pinctrl_scmi_get_group_pins,
	.pin_dbg_show = pinctrl_scmi_pin_dbg_show,
#ifdef CONFIG_OF
	.dt_node_to_map = pinctrl_scmi_dt_node_to_map,
	.dt_free_map = pinctrl_scmi_dt_free_map,
#endif
};

static int pinctrl_scmi_get_functions_count(struct pinctrl_dev *pctldev)
{
	const struct scmi_handle *handle;
	struct scmi_pinctrl *pmx;

	if (!pctldev)
		return -EINVAL;

	pmx = pinctrl_dev_get_drvdata(pctldev);

	if (!pmx || !pmx->handle)
		return -EINVAL;

	handle = pmx->handle;

	return handle->pinctrl_ops->get_functions_count(handle);
}

static const char *pinctrl_scmi_get_function_name(struct pinctrl_dev *pctldev,
						  unsigned int selector)
{
	int ret;
	const char *name;
	const struct scmi_handle *handle;
	struct scmi_pinctrl *pmx;

	if (!pctldev)
		return NULL;

	pmx = pinctrl_dev_get_drvdata(pctldev);

	if (!pmx || !pmx->handle)
		return NULL;

	handle = pmx->handle;

	ret = handle->pinctrl_ops->get_function_name(handle, selector, &name);
	if (ret) {
		dev_err(pmx->dev, "get name failed with err %d", ret);
		return NULL;
	}

	return name;
}

static int pinctrl_scmi_get_function_groups(struct pinctrl_dev *pctldev,
					    unsigned int selector,
					    const char * const **groups,
					    unsigned int * const num_groups)
{
	const unsigned int *group_ids;
	int ret, i;
	const struct scmi_handle *handle;
	struct scmi_pinctrl *pmx;

	if (!pctldev)
		return -EINVAL;

	pmx = pinctrl_dev_get_drvdata(pctldev);

	if (!pmx || !pmx->handle || !groups || !num_groups)
		return -EINVAL;

	handle = pmx->handle;

	if ((selector < pmx->nr_functions)
		&& (pmx->functions[selector].num_groups)) {
		*groups = (const char * const *)pmx->functions[selector].groups;
		*num_groups = pmx->functions[selector].num_groups;
		return 0;
	}

	ret = handle->pinctrl_ops->get_function_groups(handle, selector,
						       &pmx->functions[selector].num_groups,
						       &group_ids);
	if (ret) {
		dev_err(pmx->dev, "Unable to get function groups, err %d", ret);
		return ret;
	}

	*num_groups = pmx->functions[selector].num_groups;
	if (!*num_groups)
		return -EINVAL;

	pmx->functions[selector].groups =
		devm_kmalloc_array(pmx->dev, *num_groups,
			sizeof(*pmx->functions[selector].groups),
			GFP_KERNEL | __GFP_ZERO);
	if (!pmx->functions[selector].groups)
		return -ENOMEM;

	for (i = 0; i < *num_groups; i++) {
		pmx->functions[selector].groups[i]
			= pinctrl_scmi_get_group_name(pmx->pctldev,
						      group_ids[i]);
		if (!pmx->functions[selector].groups[i]) {
			ret = -ENOMEM;
			goto error;
		}
	}

	*groups = (const char * const *)pmx->functions[selector].groups;

	return 0;

error:
	kfree(pmx->functions[selector].groups);

	return ret;
}

static int pinctrl_scmi_func_set_mux(struct pinctrl_dev *pctldev,
				     unsigned int selector, unsigned int group)
{
	const struct scmi_handle *handle;
	struct scmi_pinctrl *pmx;

	if (!pctldev)
		return -EINVAL;

	pmx = pinctrl_dev_get_drvdata(pctldev);

	if (!pmx || !pmx->handle)
		return -EINVAL;

	handle = pmx->handle;

	return handle->pinctrl_ops->set_mux(handle, selector, group);
}

static int pinctrl_scmi_request(struct pinctrl_dev *pctldev,
				unsigned int offset)
{
	const struct scmi_handle *handle;
	struct scmi_pinctrl *pmx;

	if (!pctldev)
		return -EINVAL;

	pmx = pinctrl_dev_get_drvdata(pctldev);

	if (!pmx || !pmx->handle)
		return -EINVAL;

	handle = pmx->handle;

	return handle->pinctrl_ops->request_pin(handle, offset);
}

static int pinctrl_scmi_free(struct pinctrl_dev *pctldev, unsigned int offset)
{
	const struct scmi_handle *handle;
	struct scmi_pinctrl *pmx;

	if (!pctldev)
		return -EINVAL;

	pmx = pinctrl_dev_get_drvdata(pctldev);

	if (!pmx || !pmx->handle)
		return -EINVAL;

	handle = pmx->handle;

	return handle->pinctrl_ops->free_pin(handle, offset);
}

static const struct pinmux_ops pinctrl_scmi_pinmux_ops = {
	.request = pinctrl_scmi_request,
	.free = pinctrl_scmi_free,
	.get_functions_count = pinctrl_scmi_get_functions_count,
	.get_function_name = pinctrl_scmi_get_function_name,
	.get_function_groups = pinctrl_scmi_get_function_groups,
	.set_mux = pinctrl_scmi_func_set_mux,
};

static int pinctrl_scmi_pinconf_get(struct pinctrl_dev *pctldev,
				    unsigned int _pin,
				    unsigned long *config)
{
	const struct scmi_handle *handle;
	struct scmi_pinctrl *pmx;

	if (!pctldev)
		return -EINVAL;

	pmx = pinctrl_dev_get_drvdata(pctldev);

	if (!pmx || !pmx->handle || !config)
		return -EINVAL;

	handle = pmx->handle;

	return handle->pinctrl_ops->get_config(handle, _pin, (u32 *)config);
}

static int pinctrl_scmi_pinconf_set(struct pinctrl_dev *pctldev,
				    unsigned int _pin,
				    unsigned long *configs,
				    unsigned int num_configs)
{
	const struct scmi_handle *handle;
	int i, ret;
	struct scmi_pinctrl *pmx;

	if (!pctldev)
		return -EINVAL;

	pmx = pinctrl_dev_get_drvdata(pctldev);

	if (!pmx || !pmx->handle || !configs || num_configs == 0)
		return -EINVAL;

	handle = pmx->handle;

	for (i = 0; i < num_configs; i++) {
		ret = handle->pinctrl_ops->set_config(handle, _pin, configs[i]);
		if (ret) {
			dev_err(pmx->dev, "Error parsing config %ld\n",
				configs[i]);
			break;
		}
	}

	return ret;
}

static int pinctrl_scmi_pinconf_group_set(struct pinctrl_dev *pctldev,
					  unsigned int group,
					  unsigned long *configs,
					  unsigned int num_configs)
{
	const struct scmi_handle *handle;
	int i, ret;
	struct scmi_pinctrl *pmx;

	if (!pctldev)
		return -EINVAL;

	pmx = pinctrl_dev_get_drvdata(pctldev);

	if (!pmx || !pmx->handle || !configs || num_configs == 0)
		return -EINVAL;

	handle = pmx->handle;

	for (i = 0; i < num_configs; i++) {
		ret = handle->pinctrl_ops->set_config_group(handle, group,
							    configs[i]);
		if (ret) {
			dev_err(pmx->dev, "Error parsing config = %ld",
				configs[i]);
			break;
		}
	}

	return ret;
};

static const struct pinconf_ops pinctrl_scmi_pinconf_ops = {
	.is_generic = true,
	.pin_config_get = pinctrl_scmi_pinconf_get,
	.pin_config_set = pinctrl_scmi_pinconf_set,
	.pin_config_group_set = pinctrl_scmi_pinconf_group_set,
	.pin_config_config_dbg_show = pinconf_generic_dump_config,
};

static int pinctrl_scmi_get_pins(struct scmi_pinctrl *pmx,
				 unsigned int *nr_pins,
				 const struct pinctrl_pin_desc **pins)
{
	int ret, i;
	struct scmi_handle *handle;

	if (!pmx)
		return -EINVAL;

	handle = pmx->handle;

	if (!handle || !pins || !nr_pins)
		return -EINVAL;

	if (pmx->nr_pins) {
		*pins = pmx->pins;
		*nr_pins = pmx->nr_pins;
		return 0;
	}

	*nr_pins = handle->pinctrl_ops->get_pins_count(handle);

	pmx->nr_pins = *nr_pins;
	pmx->pins = devm_kmalloc_array(pmx->dev, *nr_pins, sizeof(*pmx->pins),
				       GFP_KERNEL);
	if (!pmx->pins)
		return -ENOMEM;

	for (i = 0; i < *nr_pins; i++) {
		pmx->pins[i].number = i;
		ret = handle->pinctrl_ops->get_pin_name(handle, i,
							&pmx->pins[i].name);
		if (ret) {
			dev_err(pmx->dev, "Can't get name for pin %d: rc %d",
				i, ret);
			goto err;
		}
	}

	*pins = pmx->pins;
	dev_dbg(pmx->dev, "got pins %d", *nr_pins);

	return 0;
 err:
	kfree(pmx->pins);
	pmx->nr_pins = 0;

	return ret;
}

static const struct scmi_device_id scmi_id_table[] = {
	{ SCMI_PROTOCOL_PINCTRL, "pinctrl" },
	{ },
};
MODULE_DEVICE_TABLE(scmi, scmi_id_table);

static int scmi_pinctrl_probe(struct scmi_device *sdev)
{
	int ret;
	struct scmi_pinctrl *pmx;

	if (!sdev || !sdev->handle)
		return -EINVAL;

	pmx = devm_kzalloc(&sdev->dev, sizeof(*pmx), GFP_KERNEL);
	if (!pmx)
		return -ENOMEM;

	pmx->handle = sdev->handle;
	if (!pmx->handle) {
		ret = -ENOMEM;
		goto clean;
	}

	pmx->dev = &sdev->dev;
	pmx->pctl_desc.name = DRV_NAME;
	pmx->pctl_desc.owner = THIS_MODULE;
	pmx->pctl_desc.pctlops = &pinctrl_scmi_pinctrl_ops;
	pmx->pctl_desc.pmxops = &pinctrl_scmi_pinmux_ops;
	pmx->pctl_desc.confops = &pinctrl_scmi_pinconf_ops;

	ret = pinctrl_scmi_get_pins(pmx, &pmx->pctl_desc.npins,
				    &pmx->pctl_desc.pins);
	if (ret)
		goto clean;

	ret = devm_pinctrl_register_and_init(&sdev->dev, &pmx->pctl_desc, pmx,
					     &pmx->pctldev);
	if (ret) {
		dev_err(&sdev->dev, "could not register: %i\n", ret);
		goto clean;
	}

	pmx->nr_functions = pinctrl_scmi_get_functions_count(pmx->pctldev);
	pmx->nr_groups = pinctrl_scmi_get_groups_count(pmx->pctldev);

	if (pmx->nr_functions) {
		pmx->functions =
			devm_kmalloc_array(&sdev->dev, pmx->nr_functions,
					   sizeof(*pmx->functions),
					   GFP_KERNEL | __GFP_ZERO);
		if (!pmx->functions) {
			ret = -ENOMEM;
			goto clean;
		}
	}

	if (pmx->nr_groups) {
		pmx->groups =
			devm_kmalloc_array(&sdev->dev, pmx->nr_groups,
					   sizeof(*pmx->groups),
					   GFP_KERNEL | __GFP_ZERO);
		if (!pmx->groups) {
			ret = -ENOMEM;
			goto clean;
		}
	}

	return pinctrl_enable(pmx->pctldev);

clean:
	if (pmx) {
		kfree(pmx->functions);
		kfree(pmx->groups);
	}

	kfree(pmx);

	return ret;
}

static struct scmi_driver scmi_pinctrl_driver = {
	.name = DRV_NAME,
	.probe = scmi_pinctrl_probe,
	.id_table = scmi_id_table,
};
module_scmi_driver(scmi_pinctrl_driver);

MODULE_AUTHOR("Oleksii Moisieiev <oleksii_moisieiev@epam.com>");
MODULE_DESCRIPTION("ARM SCMI pin controller driver");
MODULE_LICENSE("GPL v2");
