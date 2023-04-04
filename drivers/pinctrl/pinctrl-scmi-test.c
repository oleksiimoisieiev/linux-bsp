// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Power Interface (SCMI) Protocol based clock driver
 *
 * Copyright (C) 2021 EPAM.
 */
#define DEBUG

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
#define DT_PROPERTY_NAME_BUF_MAX 32

struct scmi_pinctrl_funcs {
	unsigned num_groups;
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
	unsigned nr_pins;
};

static struct scmi_pinctrl *pmx;
//TODO test

static int pinctrl_scmi_get_groups_count(struct pinctrl_dev *pctldev)
{
	const struct scmi_handle *handle = pmx->handle;

	return handle->pinctrl_ops->get_groups_count(handle);
}

static const char *pinctrl_scmi_get_group_name(struct pinctrl_dev *pctldev,
					       unsigned selector)
{
	int ret;
	const char *name;
	const struct scmi_handle *handle;

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
//TODO test

static int pinctrl_scmi_get_group_pins(struct pinctrl_dev *pctldev,
				unsigned selector, const unsigned **pins, unsigned *num_pins)
{
	const struct scmi_handle *handle = pmx->handle;

	return handle->pinctrl_ops->get_group_pins(handle, selector,
											   pins, num_pins);
}
//TODO test

static void pinctrl_scmi_pin_dbg_show(struct pinctrl_dev *pctldev, struct seq_file *s,
				unsigned offset)
{
	seq_puts(s, DRV_NAME);
}
//TODO test

static const char *int_to_str_alloc(unsigned int param)
{
	char buf[DT_PROPERTY_NAME_BUF_MAX];
	char *res;
	int size;

	size = snprintf(buf, DT_PROPERTY_NAME_BUF_MAX, "%u", param);
	if (!size)
		return NULL;

	res = kmemdup(buf, size + 1, GFP_KERNEL);
	return res;
}
//TODO test

static void str_from_int_free(const char *addr)
{
	if (likely(addr))
		kfree(addr);
}

//TODO test
#ifdef CONFIG_OF
static void pinctrl_scmi_dt_free_map(struct pinctrl_dev *pctldev,
			       struct pinctrl_map *map, unsigned num_maps)
{
	unsigned int i;

	if (map == NULL)
		return;

	for (i = 0; i < num_maps; ++i) {
		if (map[i].type == PIN_MAP_TYPE_CONFIGS_GROUP ||
		    map[i].type == PIN_MAP_TYPE_CONFIGS_PIN) {
			kfree(map[i].data.configs.configs);
			str_from_int_free(map[i].data.configs.group_or_pin);
		}

		if (map[i].type == PIN_MAP_TYPE_MUX_GROUP)
			str_from_int_free(map[i].data.mux.function);
	}

	kfree(map);
}
//TODO test

static int pinctrl_scmi_map_add_config(struct pinctrl_map *map,
				 const char *group_or_pin,
				 enum pinctrl_map_type type,
				 unsigned long *configs,
				 unsigned int num_configs)
{
	unsigned long *cfgs;

	cfgs = kmemdup(configs, num_configs * sizeof(*cfgs),
		       GFP_KERNEL);
	if (cfgs == NULL)
		return -ENOMEM;

	map->type = type;
	map->data.configs.group_or_pin = group_or_pin;
	map->data.configs.configs = cfgs;
	map->data.configs.num_configs = num_configs;

	return 0;
}
//TODO test

static int pinctrl_scmi_dt_subnode_to_map(struct pinctrl_dev *pctldev,
				    struct device_node *np,
				    struct pinctrl_map **map,
				    unsigned int *num_maps, unsigned int *index)
{
	struct device *dev = pmx->dev;
	struct pinctrl_map *maps = *map;
	unsigned int nmaps = *num_maps;
	unsigned int idx = *index;
	unsigned int num_configs;
	u32 function;
	bool func_set = false;
	unsigned long *configs;
	struct property *prop;
	unsigned int num_groups;
	unsigned int num_pins;
	u32 group;
	u32 pin;
	const __be32 *cur;

	int ret;
	const char *func_prop_name = "function";
	const char *groups_prop_name = "groups";
	const char *pins_prop_name = "pins";

	ret = of_property_read_u32(np, func_prop_name, &function);
	if (ret == -EINVAL) {
		func_set = false;
	} else if (ret < 0) {
		dev_err(dev, "Invalid function in DT\n");
		return ret;
	} else {
		func_set = true;
	}

	dev_dbg(pmx->dev, "name = %s", np->full_name);
	dev_dbg(pmx->dev, "func = %d, is set = %d\n", function, func_set);

	ret = pinconf_generic_parse_dt_config(np, NULL, &configs, &num_configs);
	if (ret < 0)
		return ret;

	if (!func_set && num_configs == 0) {
		dev_err(dev,
			"DT node must contain at least a function or config\n");
		ret = -ENODEV;
		goto done;
	}

	ret = of_property_count_u32_elems(np, pins_prop_name);
	if (ret == -EINVAL) {
		num_pins = 0;
	} else if (ret < 0) {
		dev_err(dev, "Invalid pins list in DT\n");
		goto done;
	} else {
		num_pins = ret;
	}

	ret = of_property_count_u32_elems(np, groups_prop_name);
	if (ret == -EINVAL) {
		num_groups = 0;
	} else if (ret < 0) {
		dev_err(dev, "Invalid pin groups list in DT\n");
		goto done;
	} else {
		num_groups = ret;
	}

	if (!num_pins && !num_groups) {
		dev_err(dev, "No pin or group provided in DT node\n");
		ret = -ENODEV;
		goto done;
	}

	if (func_set)
		nmaps += num_groups;

	if (configs)
		nmaps += num_pins + num_groups;

	maps = krealloc(maps, sizeof(*maps) * nmaps, GFP_KERNEL);
	if (maps == NULL) {
		ret = -ENOMEM;
		goto done;
	}

	*map = maps;
	*num_maps = nmaps;

	of_property_for_each_u32(np, groups_prop_name, prop, cur, group) {
		const char *group_name = int_to_str_alloc(group);
		if (!group_name) {
			ret = -EINVAL;
			goto done;
		}

		if (func_set) {
			maps[idx].type = PIN_MAP_TYPE_MUX_GROUP;
			maps[idx].data.mux.group = group_name;

			maps[idx].data.mux.function = int_to_str_alloc(function);
			if (!maps[idx].data.mux.function) {
				ret = -EINVAL;
				goto done;
			}

			idx++;
		}

		if (configs) {
			ret = pinctrl_scmi_map_add_config(&maps[idx], group_name,
						    PIN_MAP_TYPE_CONFIGS_GROUP,
						    configs, num_configs);
			if (ret < 0)
				goto done;

			idx++;
		}
	}

	if (!configs) {
		ret = 0;
		goto done;
	}

	of_property_for_each_u32(np, pins_prop_name, prop, cur, pin) {
		const char *pin_name = int_to_str_alloc(pin);
		if (!pin_name) {
			ret = -EINVAL;
			goto done;
		}

		ret = pinctrl_scmi_map_add_config(&maps[idx], pin_name,
					    PIN_MAP_TYPE_CONFIGS_PIN,
					    configs, num_configs);
		if (ret < 0)
			goto done;

		idx++;
	}

done:
	*index = idx;
	kfree(configs);
	return ret;
}
//TODO test

static int pinctrl_scmi_dt_node_to_map(struct pinctrl_dev *pctldev,
				 struct device_node *np,
				 struct pinctrl_map **map, unsigned *num_maps)
{
	struct device *dev = pmx->dev;
	struct device_node *child;
	unsigned int index;
	int ret;

	*map = NULL;
	*num_maps = 0;
	index = 0;

	for_each_child_of_node(np, child) {
		ret = pinctrl_scmi_dt_subnode_to_map(pctldev, child, map, num_maps,
					       &index);
		if (ret < 0) {
			of_node_put(child);
			goto done;
		}
	}

	/* If no mapping has been found in child nodes try the config node. */
	if (*num_maps == 0) {
		ret = pinctrl_scmi_dt_subnode_to_map(pctldev, np, map, num_maps,
					       &index);
		if (ret < 0)
			goto done;
	}

	if (*num_maps)
		return 0;

	dev_err(dev, "no mapping found in node %pOF\n", np);
	ret = -EINVAL;

done:
	if (ret < 0)
		pinctrl_scmi_dt_free_map(pctldev, *map, *num_maps);

	return ret;
}
#endif /* CONFIG_OF */

static const struct pinctrl_ops pinctrl_scmi_pinctrl_ops = {
	.get_groups_count	= pinctrl_scmi_get_groups_count,
	.get_group_name		= pinctrl_scmi_get_group_name,
	.get_group_pins		= pinctrl_scmi_get_group_pins,
	.pin_dbg_show		= pinctrl_scmi_pin_dbg_show,
#ifdef CONFIG_OF
	.dt_node_to_map = pinctrl_scmi_dt_node_to_map,
	.dt_free_map = pinctrl_scmi_dt_free_map,
#endif
};
//TODO test

static int pinctrl_scmi_get_functions_count(struct pinctrl_dev *pctldev)
{
	const struct scmi_handle *handle = pmx->handle;

	return handle->pinctrl_ops->get_functions_count(handle);
}
//TODO test

static const char *pinctrl_scmi_get_function_name(struct pinctrl_dev *pctldev,
					    unsigned selector)
{
	int ret;
	const char *name;
	const struct scmi_handle *handle = pmx->handle;

	ret = handle->pinctrl_ops->get_function_name(handle, selector, &name);
	if (ret) {
		dev_err(pmx->dev, "get name failed with err %d", ret);
		return "";
	}

	return name;
}
//TODO test

static int pinctrl_scmi_get_function_groups(struct pinctrl_dev *pctldev,
				      unsigned selector,
				      const char * const **groups,
				      unsigned * const num_groups)
{
	const u16 *group_ids;
	const struct scmi_handle *handle = pmx->handle;
	int ret, i;

	if ((selector < pmx->nr_functions)
		&& (pmx->functions[selector].num_groups)) {
		dev_dbg(pmx->dev, "1");
		*groups = (const char * const *)pmx->functions[selector].groups;
		*num_groups = pmx->functions[selector].num_groups;
		return 0;
	}

	ret = handle->pinctrl_ops->get_function_groups(handle, selector,
					&pmx->functions[selector].num_groups, &group_ids);
	if (ret) {
		dev_err(pmx->dev, "Unable to get function groups, err %d", ret);
		return ret;
	}

	*num_groups = pmx->functions[selector].num_groups;

	pmx->functions[selector].groups = devm_kzalloc(pmx->dev,
			sizeof(*pmx->functions[selector].groups) * *num_groups,
			GFP_KERNEL);
	if (unlikely(!pmx->functions[selector].groups))
		return -ENOMEM;

	for (i = 0; i < *num_groups; i++) {
		pmx->functions[selector].groups[i] = int_to_str_alloc(group_ids[i]);
		if (unlikely(!pmx->functions[selector].groups[i])) {
			ret = -ENOMEM;
			goto error;
		}
	}

	*groups = (const char * const *)pmx->functions[selector].groups;
	dev_dbg(pmx->dev, "got groups %d", *num_groups);

	return 0;

error:
	if (pmx->functions[selector].num_groups) {
		for (i = 0; i < pmx->functions[selector].num_groups; i++) {
			if (pmx->functions[selector].groups[i])
				str_from_int_free(pmx->functions[selector].groups[i]);
		}

		kfree(pmx->functions[selector].groups);
	}

	return ret;
}
//TODO test

static int pinctrl_scmi_func_set_mux(struct pinctrl_dev *pctldev,
				      unsigned selector, unsigned group)
{
	const struct scmi_handle *handle = pmx->handle;

	return handle->pinctrl_ops->set_mux(handle, selector, group);
}
//TODO test

static int pinctrl_scmi_request(struct pinctrl_dev *pctldev, unsigned offset)
{
	const struct scmi_handle *handle = pmx->handle;

	return handle->pinctrl_ops->request_pin(handle, offset);
}
//TODO test

static int pinctrl_scmi_free(struct pinctrl_dev *pctldev, unsigned offset)
{
	const struct scmi_handle *handle = pmx->handle;

	return handle->pinctrl_ops->free_pin(handle, offset);
}
//TODO test

static const struct pinmux_ops pinctrl_scmi_pinmux_ops = {
	.request	= pinctrl_scmi_request,
	.free	= pinctrl_scmi_free,
	.get_functions_count	= pinctrl_scmi_get_functions_count,
	.get_function_name	= pinctrl_scmi_get_function_name,
	.get_function_groups	= pinctrl_scmi_get_function_groups,
	.set_mux		= pinctrl_scmi_func_set_mux,
};
//TODO test

static int pinctrl_scmi_pinconf_get(struct pinctrl_dev *pctldev, unsigned _pin,
			      unsigned long *config)
{
	const struct scmi_handle *handle;

	if (!pmx || !pmx->handle || !config)
		return -EINVAL;

	handle = pmx->handle;

	return handle->pinctrl_ops->get_config(handle, _pin, (u32 *)config);
}
//TODO test

static int pinctrl_scmi_pinconf_set(struct pinctrl_dev *pctldev, unsigned _pin,
			      unsigned long *configs, unsigned num_configs)
{
	const struct scmi_handle *handle = pmx->handle;
	int i, ret;

	dev_dbg(pmx->dev, "Enter pin = %d, num_configs = %d\n", _pin, num_configs);

	for (i=0; i<num_configs; i++) {
		ret = handle->pinctrl_ops->set_config(handle, _pin, configs[i]);
		if (ret) {
			dev_err(pmx->dev, "Error parsing config %ld\n", configs[i]);
			break;
		}
	}

	return ret;
}
//TODO test
static int pinctrl_scmi_pinconf_group_set(struct pinctrl_dev *pctldev,
				    unsigned group,
				    unsigned long *configs,
				    unsigned num_configs)
{
	const struct scmi_handle *handle = pmx->handle;
	int i, ret;

	for (i=0; i<num_configs; i++) {
		ret = handle->pinctrl_ops->set_config_group(handle, group, configs[i]);
		if (ret) {
			dev_err(pmx->dev, "Error parsing config = %ld", configs[i]);
			break;
		}
	}

	return ret;
};

static const struct pinconf_ops pinctrl_scmi_pinconf_ops = {
	.is_generic			= true,
	.pin_config_get			= pinctrl_scmi_pinconf_get,
	.pin_config_set			= pinctrl_scmi_pinconf_set,
	.pin_config_group_set		= pinctrl_scmi_pinconf_group_set,
	.pin_config_config_dbg_show	= pinconf_generic_dump_config,
};

static int pinctrl_scmi_get_pins(struct scmi_handle *handle,
				 unsigned *nr_pins,
				 const struct pinctrl_pin_desc **pins)
{
	const u16 *pin_ids;
	int ret, i;

	if (pmx->nr_pins) {
		*pins = pmx->pins;
		*nr_pins = pmx->nr_pins;
		return 0;
	}

	ret = handle->pinctrl_ops->get_pins(handle, nr_pins, &pin_ids);
	if (ret) {
		dev_err(pmx->dev, "get pins failed with err %d", ret);
		return ret;
	}

	pmx->nr_pins = *nr_pins;
	pmx->pins = devm_kzalloc(pmx->dev, sizeof(*pmx->pins) * *nr_pins,
							 GFP_KERNEL);
	if (unlikely(!pmx->pins))
		return -ENOMEM;

	for (i = 0; i < *nr_pins; i++) {
		pmx->pins[i].number = pin_ids[i];
		pmx->pins[i].name = int_to_str_alloc(pin_ids[i]);
	}

	*pins = pmx->pins;
	dev_dbg(pmx->dev, "got pins %d", *nr_pins);

	return 0;
}

static const struct scmi_device_id scmi_id_table[] = {
	{ SCMI_PROTOCOL_PINCTRL, "pinctrl" },
	{ },
};
MODULE_DEVICE_TABLE(scmi, scmi_id_table);




#define tst_head(x)						\
	do {							\
		printk("********** %s START  *********\n", x);	\
	} while (0);

#define tst_chk(x, fmt, ...)						\
	do {								\
		if (!(x)) {						\
			printk("*** %s %d " fmt "***\n", __func__, __LINE__, \
			       __VA_ARGS__);				\
			return -EINVAL;					\
		} else {						\
			printk("***** %s %d passed ****\n", __func__, __LINE__); \
		} } while (0);

static int conf_tests(void)
{
	const struct scmi_handle *handle = pmx->handle;
	__u32 lconfig;
	unsigned long config;
	int ret;
	tst_head("ops->get_config");

	lconfig = 4; /*bias-pull-up */
	ret = handle->pinctrl_ops->set_config(handle, 0, lconfig);
	tst_chk(ret == 0, "Unexpected ret %d", ret);

	lconfig = 4; /*bias-pull-up */
	ret = handle->pinctrl_ops->get_config(handle, 0, &lconfig);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	tst_chk(lconfig == 1022, "Unexpected config %d", lconfig);










	lconfig = 10; /*drive strength */
	ret = handle->pinctrl_ops->get_config(handle, 0, &lconfig);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	tst_chk(lconfig == 3, "Unexpected config %d", lconfig);

	lconfig = 4; /*bias-pull-up */
	ret = handle->pinctrl_ops->get_config(handle, 0, &lconfig);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	tst_chk(lconfig == 3, "Unexpected config %d", lconfig);

	lconfig = 19; /*power-source */
	ret = handle->pinctrl_ops->get_config(handle, 1, &lconfig);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	tst_chk(lconfig == 3, "Unexpected config %d", lconfig);

	lconfig = 4; /*bias-pull-up */
	ret = handle->pinctrl_ops->get_config(handle, 24, &lconfig);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	tst_chk(lconfig == 3, "Unexpected config %d", lconfig);

	lconfig = 4; /*bias-pull-up */
	ret = handle->pinctrl_ops->get_config(handle, 999, &lconfig);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	tst_chk(lconfig == 3, "Unexpected config %d", lconfig);

	lconfig = 0;
	ret = handle->pinctrl_ops->get_config(handle, 1, &lconfig);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	tst_chk(lconfig == 3, "Unexpected config %d", lconfig);

	lconfig = 999;
	ret = handle->pinctrl_ops->get_config(handle, 1, &lconfig);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	tst_chk(lconfig == 3, "Unexpected config %d", lconfig);

	lconfig = 1; /*bias-bus-hold */
	ret = handle->pinctrl_ops->get_config(handle, 1, NULL);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	tst_chk(lconfig == 3, "Unexpected config %d", lconfig);

	lconfig = 999; /*bias-bus-hold */
	ret = handle->pinctrl_ops->get_config(NULL, 1, &lconfig);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	tst_chk(lconfig == 3, "Unexpected config %d", lconfig);


	tst_head("ops->get_config");
	config = 1; /*bias-bus-hold */
	ret = pinctrl_scmi_pinconf_get(pmx->pctldev, 0, &config);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	tst_chk(config == 3, "Unexpected config %ld", config);

	config = 1; /*bias-bus-hold */
	ret = pinctrl_scmi_pinconf_get(pmx->pctldev, 1, &config);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	tst_chk(config == 3, "Unexpected config %ld", config);

	config = 1; /*bias-bus-hold */
	ret = pinctrl_scmi_pinconf_get(pmx->pctldev, 24, &config);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	tst_chk(config == 3, "Unexpected config %ld", config);

	config = 1; /*bias-bus-hold */
	ret = pinctrl_scmi_pinconf_get(pmx->pctldev, 999, &config);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	tst_chk(config == 3, "Unexpected config %ld", config);

	config = 0; /*bias-bus-hold */
	ret = pinctrl_scmi_pinconf_get(pmx->pctldev, 1, &config);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	tst_chk(config == 3, "Unexpected config %ld", config);

	config = 999; /*bias-bus-hold */
	ret = pinctrl_scmi_pinconf_get(pmx->pctldev, 1, &config);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	tst_chk(config == 3, "Unexpected config %ld", config);

	config = 1; /*bias-bus-hold */
	ret = pinctrl_scmi_pinconf_get(pmx->pctldev, 1, NULL);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	tst_chk(config == 3, "Unexpected config %ld", config);

	config = 999; /*bias-bus-hold */
	ret = pinctrl_scmi_pinconf_get(NULL, 1, NULL);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	tst_chk(config == 3, "Unexpected config %ld", config);
	return 0;
}

static int grfn_getinfo_test(void)
{
	const struct scmi_handle *handle = pmx->handle;
	int ret;
	const char *name;
	tst_head("ops->get_group_name");

	ret = handle->pinctrl_ops->get_group_name(handle, 0, &name);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	printk("name = %s", name);
	kfree(name);

	ret = handle->pinctrl_ops->get_group_name(handle, 0, &name);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	printk("name = %s", name);
	kfree(name);

	ret = handle->pinctrl_ops->get_group_name(handle, 15, &name);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	printk("name = %s", name);
	kfree(name);

	ret = handle->pinctrl_ops->get_group_name(handle, 15, &name);
	tst_chk(ret == 0, "Unexpected ret %d", ret);
	printk("name = %s", name);
	kfree(name);

	ret = handle->pinctrl_ops->get_group_name(handle, 999, &name);
	tst_chk(ret == -22, "Unexpected ret %d", ret);
	printk("name = %s", name);

	ret = handle->pinctrl_ops->get_group_name(handle, 990, &name);
	tst_chk(ret == -22, "Unexpected ret %d", ret);
	printk("name = %s", name);

	name = pinctrl_scmi_get_group_name(pmx->pctldev, 0);
	tst_chk(name != 0, "Unexpected name %d", -1);
	printk("name = %s", name);
	kfree(name);

	name = pinctrl_scmi_get_group_name(pmx->pctldev, 0);
	tst_chk(name !=0, "Unexpected name %d", -1);
	printk("name = %s", name);
	kfree(name);

	name = pinctrl_scmi_get_group_name(pmx->pctldev, 14);
	tst_chk(name != 0, "Unexpected name %d", -1);
	printk("name = %s", name);
	kfree(name);

	name = pinctrl_scmi_get_group_name(pmx->pctldev, 14);
	tst_chk(name !=0, "Unexpected name %d", -1);
	printk("name = %s", name);
	kfree(name);

	name = pinctrl_scmi_get_group_name(pmx->pctldev, 999);
	tst_chk(name == 0, "Unexpected name %d", -1);

	name = pinctrl_scmi_get_group_name(pmx->pctldev, 999);
	tst_chk(name == 0, "Unexpected name %d", -1);

	name = pinctrl_scmi_get_group_name(NULL, 999);
	tst_chk(name == 0, "Unexpected name %d", -1);

	return 0;
}


static int run_tests(void)
{
	int ret;

	ret = grfn_getinfo_test();
	if (ret)
		return ret;


	/* ret = conf_tests(); */
	/* if (ret) */
	/* 	return ret; */

	return 0;
}

static int scmi_pinctrl_probe(struct scmi_device *sdev)
{
	int ret;

	pmx = devm_kzalloc(&sdev->dev, sizeof(*pmx), GFP_KERNEL);
	if (unlikely(!pmx))
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

	ret = pinctrl_scmi_get_pins(pmx->handle, &pmx->pctl_desc.npins,
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
		pmx->functions = devm_kzalloc(&sdev->dev, sizeof(*pmx->functions) *
								  pmx->nr_functions, GFP_KERNEL);
		if (unlikely(!pmx->functions)) {
			ret = -ENOMEM;
			goto clean;
		}
	}

	if (pmx->nr_groups) {
		pmx->groups = devm_kzalloc(&sdev->dev, sizeof(*pmx->groups) *
							   pmx->nr_groups, GFP_KERNEL);
		if (unlikely(!pmx->groups)) {
			ret = -ENOMEM;
			goto clean;
		}
	}

	/********************/
	ret = run_tests();
	if (ret) {
		printk("TESTS FAILED!\n");
		return -EINVAL;
	}

	printk("TESTS PASSED!\n");
	return -EINVAL;
        /**********************/
	return pinctrl_enable(pmx->pctldev);

clean:
	if (pmx) {
		if (pmx->functions)
			kfree(pmx->functions);

		if (pmx->groups)
			kfree(pmx->groups);

		kfree(pmx);
	}

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
