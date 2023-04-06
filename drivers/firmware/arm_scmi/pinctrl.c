// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) Pinctrl Protocol
 *
 * Copyright (C) 2021 EPAM.
 */

#define pr_fmt(fmt) "SCMI Notifications PINCTRL - " fmt

#include <linux/scmi_protocol.h>
#include <linux/slab.h>

#include "common.h"
#include "notify.h"

#define SET_TYPE(x) ((x) & 0x3)

enum scmi_pinctrl_protocol_cmd {
	PINCTRL_ATTRIBUTES = 0x3,
	PINCTRL_LIST_ASSOCIATIONS = 0x4,
	PINCTRL_CONFIG_GET = 0x5,
	PINCTRL_CONFIG_SET = 0x6,
	PINCTRL_FUNCTION_SELECT = 0x7,
	PINCTRL_REQUEST = 0x8,
	PINCTRL_RELEASE = 0x9,
	PINCTRL_NAME_GET = 0xa,
	PINCTRL_SET_PERMISSIONS = 0xb
};

enum scmi_pinctrl_selector_type {
	PIN_TYPE = 0,
	GROUP_TYPE,
	FUNCTION_TYPE
};

struct scmi_group_info {
	bool present;
	char *name;
	unsigned *group_pins;
	unsigned nr_pins;
};

struct scmi_function_info {
	bool present;
	char *name;
	unsigned *groups;
	unsigned nr_groups;
};

struct scmi_pin_info {
	bool present;
	char *name;
};

struct scmi_pinctrl_info {
	u32 version;
	u16 nr_groups;
	u16 nr_functions;
	u16 nr_pins;
	struct scmi_group_info *groups;
	struct scmi_function_info *functions;
	struct scmi_pin_info *pins;
};

struct scmi_conf_tx {
	__le32 identifier;
#define SET_TYPE_BITS(attr, x) (((attr) & 0xFFFFFCFF) | (x & 0x3) << 8)
#define SET_CONFIG(attr, x) ((attr) & 0xFF) | (x & 0xFF)
	__le32 attributes;
};

static int scmi_pinctrl_attributes_get(const struct scmi_handle *handle,
				       struct scmi_pinctrl_info *pi)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_msg_pinctrl_protocol_attributes {
#define GROUPS_NR(x) ((x) >> 16)
#define PINS_NR(x) ((x) & 0xffff)
		__le32 attributes_low;
#define FUNCTIONS_NR(x) ((x) & 0xffff)
		__le32 attributes_high;
	} *attr;

	if (!pi)
		return -EINVAL;

	ret = scmi_xfer_get_init(handle, PROTOCOL_ATTRIBUTES,
				 SCMI_PROTOCOL_PINCTRL, 0, sizeof(*attr), &t);
	if (ret)
		return ret;

	attr = t->rx.buf;

	ret = scmi_do_xfer(handle, t);
	if (!ret) {
		pi->nr_functions =
			le16_to_cpu(FUNCTIONS_NR(attr->attributes_high));
		pi->nr_groups = le16_to_cpu(GROUPS_NR(attr->attributes_low));
		pi->nr_pins = le16_to_cpu(PINS_NR(attr->attributes_low));
	}

	scmi_xfer_put(handle, t);
	return ret;
}

static int scmi_pinctrl_get_groups_count(const struct scmi_handle *handle)
{
	struct scmi_pinctrl_info *pi;

	if (!handle || !handle->pinctrl_priv)
		return -ENODEV;

	pi = handle->pinctrl_priv;

	return pi->nr_groups;
}

static int scmi_pinctrl_get_pins_count(const struct scmi_handle *handle)
{
	struct scmi_pinctrl_info *pi;

	if (!handle || !handle->pinctrl_priv)
		return -ENODEV;

	pi = handle->pinctrl_priv;

	return pi->nr_pins;
}

static int scmi_pinctrl_get_functions_count(const struct scmi_handle *handle)
{
	struct scmi_pinctrl_info *pi;

	if (!handle || !handle->pinctrl_priv)
		return -ENODEV;

	pi = handle->pinctrl_priv;

	return pi->nr_functions;
}

static int scmi_pinctrl_validate_id(const struct scmi_handle *handle,
				    u32 identifier,
				    enum scmi_pinctrl_selector_type type)
{
	struct scmi_pinctrl_info *pi;

	if (!handle || !handle->pinctrl_priv)
		return -ENODEV;

	switch (type) {
	case PIN_TYPE:
		pi = handle->pinctrl_priv;

		return (identifier < pi->nr_pins) ? 0 : -EINVAL;
	case GROUP_TYPE:
		return (identifier <
			scmi_pinctrl_get_groups_count(handle)) ?
			0 : -EINVAL;
	case FUNCTION_TYPE:
		return (identifier <
			scmi_pinctrl_get_functions_count(handle)) ?
			0 : -EINVAL;
	default:
		return -EINVAL;
	}
}

static int scmi_pinctrl_get_name(const struct scmi_handle *handle,
				 u32 identifier,
				 enum scmi_pinctrl_selector_type type,
				 char **name)
{
	struct scmi_xfer *t;
	int ret = 0;
	struct scmi_name_tx {
		__le32 identifier;
		__le32 flags;
	} *tx;
	struct scmi_name_rx {
		__le32 flags;
		u8 name[64];
	} *rx;

	if (!handle || !name) {
		return -EINVAL;
	}

	ret = scmi_pinctrl_validate_id(handle, identifier, type);
	if (ret)
		return ret;

	ret = scmi_xfer_get_init(handle, PINCTRL_NAME_GET,
				 SCMI_PROTOCOL_PINCTRL,
				 sizeof(*tx), sizeof(*rx), &t);

	tx = t->tx.buf;
	rx = t->rx.buf;
	tx->identifier = identifier;
	tx->flags = SET_TYPE(cpu_to_le32(type));

	ret = scmi_do_xfer(handle, t);
	if (ret)
		goto out;

	if (rx->flags) {
		ret = -EINVAL;
		goto out;
	}

	*name = kasprintf(GFP_KERNEL, "%s", rx->name);
	if (!*name) {
		ret = -ENOMEM;
	}
 out:
	scmi_xfer_put(handle, t);

	return ret;
}

static int scmi_pinctrl_attributes(const struct scmi_handle *handle,
				   enum scmi_pinctrl_selector_type type,
				   u32 selector, char **name, unsigned *n_elems)
{
	int ret = 0;
	struct scmi_xfer *t;
	struct scmi_pinctrl_attributes_tx {
		__le32 identifier;
		__le32 flags;
	} *tx;
	struct scmi_pinctrl_attributes_rx {
#define EXT_NAME_FLAG(x) ((x) & BIT(31))
#define NUM_ELEMS(x) ((x) & 0xffff)
		__le32 attributes;
		u8 name[16];
	} *rx;

	if (!handle || !name)
		return -EINVAL;

	ret = scmi_pinctrl_validate_id(handle, selector, type);
	if (ret)
		return ret;

	ret = scmi_xfer_get_init(handle, PINCTRL_ATTRIBUTES,
			 SCMI_PROTOCOL_PINCTRL, sizeof(*tx), sizeof(*rx), &t);
	if (ret)
		return ret;

	tx = t->tx.buf;
	rx = t->rx.buf;
	tx->identifier = selector;
	tx->flags = SET_TYPE(cpu_to_le32(type));

	ret = scmi_do_xfer(handle, t);
	if (ret)
		goto out;

	*n_elems = NUM_ELEMS(rx->attributes);

	if (!EXT_NAME_FLAG(rx->attributes)) {
		*name = kasprintf(GFP_KERNEL, "%s", rx->name);
		if (!*name)
			ret = -ENOMEM;
	} else
		ret = scmi_pinctrl_get_name(handle, selector, type, name);
 out:
	scmi_xfer_put(handle, t);
	return ret;
}

static int scmi_pinctrl_list_associations(const struct scmi_handle *handle,
					  u32 selector,
					  enum scmi_pinctrl_selector_type type,
					  uint16_t size, unsigned *array)
{
	struct scmi_xfer *t;
	struct scmi_pinctrl_list_assoc_tx {
		__le32 identifier;
		__le32 flags;
		__le32 index;
	} *tx;
	struct scmi_pinctrl_list_assoc_rx {
#define RETURNED(x) ((x) & 0xFFF)
#define REMAINING(x) ((x) >> 16)
		__le32 flags;
		__le16 array[];
	} *rx;
	u16 tot_num_ret = 0, loop_num_ret;
	u16 remaining_num_ret;
	int ret, loop;

	if (!handle || !array || !size)
		return -EINVAL;

	if (type == PIN_TYPE)
		return -EINVAL;

	ret = scmi_pinctrl_validate_id(handle, selector, type);
	if (ret)
		return ret;

	ret = scmi_xfer_get_init(handle, PINCTRL_LIST_ASSOCIATIONS,
				 SCMI_PROTOCOL_PINCTRL, sizeof(*tx),
				 0, &t);
	if (ret)
		return ret;

	tx = t->tx.buf;
	rx = t->rx.buf;

	do {
		tx->identifier = cpu_to_le32(selector);
		tx->flags = SET_TYPE(cpu_to_le32(type));
		tx->index = cpu_to_le32(tot_num_ret);

		ret = scmi_do_xfer(handle, t);
		if (ret)
			break;

		loop_num_ret = le32_to_cpu(RETURNED(rx->flags));
		remaining_num_ret = le32_to_cpu(REMAINING(rx->flags));

		for (loop = 0; loop < loop_num_ret; loop++) {
			if (tot_num_ret + loop >= size) {
				ret = -EMSGSIZE;
				goto out;
			}

			array[tot_num_ret + loop] =
				le16_to_cpu(rx->array[loop]);
		}

		tot_num_ret += loop_num_ret;

		scmi_reset_rx_to_maxsz(handle, t);
	} while (remaining_num_ret > 0);
out:
	scmi_xfer_put(handle, t);
	return ret;
}

static int scmi_pinctrl_request_config(const struct scmi_handle *handle,
				       u32 selector,
				       enum scmi_pinctrl_selector_type type,
				       u32 *config)
{
	struct scmi_xfer *t;
	struct scmi_conf_tx *tx;
	__le32 *packed_config;
	u32 attributes = 0;
	int ret;

	if (!handle || !config || type == FUNCTION_TYPE)
		return -EINVAL;

	ret = scmi_pinctrl_validate_id(handle, selector, type);
	if (ret)
		return ret;

	ret = scmi_xfer_get_init(handle, PINCTRL_CONFIG_GET,
				 SCMI_PROTOCOL_PINCTRL,
				 sizeof(*tx), sizeof(*packed_config), &t);
	if (ret)
		return ret;

	tx = t->tx.buf;
	packed_config = t->rx.buf;
	tx->identifier = cpu_to_le32(selector);
	attributes = SET_TYPE_BITS(attributes, type);
	attributes = SET_CONFIG(attributes, *config);

	tx->attributes = cpu_to_le32(attributes);

	ret = scmi_do_xfer(handle, t);

	if (!ret)
		*config = le32_to_cpu(*packed_config);

	scmi_xfer_put(handle, t);
	return ret;
}

static int scmi_pinctrl_get_config(const struct scmi_handle *handle, u32 pin,
				   u32 *config)
{
	return scmi_pinctrl_request_config(handle, pin, PIN_TYPE, config);
}

static int scmi_pinctrl_apply_config(const struct scmi_handle *handle,
				     u32 selector,
				     enum scmi_pinctrl_selector_type type,
				     u32 config)
{
	struct scmi_xfer *t;
	struct scmi_conf_tx *tx;
	u32 attributes = 0;
	int ret;

	if (!handle || type == FUNCTION_TYPE)
		return -EINVAL;

	ret = scmi_pinctrl_validate_id(handle, selector, type);
	if (ret)
		return ret;

	ret = scmi_xfer_get_init(handle, PINCTRL_CONFIG_SET,
				 SCMI_PROTOCOL_PINCTRL,
				 sizeof(*tx), 0, &t);
	if (ret)
		return ret;

	tx = t->tx.buf;
	tx->identifier = cpu_to_le32(selector);
	attributes = SET_TYPE_BITS(attributes, type);
	attributes = SET_CONFIG(attributes, config);
	tx->attributes = cpu_to_le32(attributes);

	ret = scmi_do_xfer(handle, t);

	scmi_xfer_put(handle, t);
	return ret;
}

static int scmi_pinctrl_set_config(const struct scmi_handle *handle, u32 pin,
				   u32 config)
{
	return scmi_pinctrl_apply_config(handle, pin, PIN_TYPE, config);
}

static int scmi_pinctrl_get_config_group(const struct scmi_handle *handle,
					 u32 group, u32 *config)
{
	return scmi_pinctrl_request_config(handle, group, GROUP_TYPE, config);
}

static int scmi_pinctrl_set_config_group(const struct scmi_handle *handle,
					 u32 group, u32 config)
{
	return scmi_pinctrl_apply_config(handle, group, GROUP_TYPE, config);
}

static int scmi_pinctrl_function_select(const struct scmi_handle *handle,
					u32 identifier,
					enum scmi_pinctrl_selector_type type,
					u32 function_id)
{
	struct scmi_xfer *t;
	struct scmi_func_set_tx {
		__le32 identifier;
		__le32 function_id;
		__le32 flags;
	} *tx;
	int ret;

	if (!handle || type == FUNCTION_TYPE)
		return -EINVAL;

	ret = scmi_pinctrl_validate_id(handle, identifier, type);
	if (ret)
		return ret;

	ret = scmi_xfer_get_init(handle, PINCTRL_FUNCTION_SELECT,
				 SCMI_PROTOCOL_PINCTRL,
				 sizeof(*tx), 0, &t);
	if (ret)
		return ret;

	tx = t->tx.buf;
	tx->identifier = cpu_to_le32(identifier);
	tx->function_id = cpu_to_le32(function_id);
	tx->flags = SET_TYPE(cpu_to_le32(type));

	ret = scmi_do_xfer(handle, t);
	scmi_xfer_put(handle, t);

	return ret;
}

static int scmi_pinctrl_request(const struct scmi_handle *handle,
				u32 identifier,
				enum scmi_pinctrl_selector_type type)
{
	struct scmi_xfer *t;
	int ret;
	struct scmi_request_tx {
		__le32 identifier;
		__le32 flags;
	} *tx;

	if (!handle || type == FUNCTION_TYPE)
		return -EINVAL;

	ret = scmi_pinctrl_validate_id(handle, identifier, type);
	if (ret)
		return ret;

	ret = scmi_xfer_get_init(handle, PINCTRL_REQUEST, SCMI_PROTOCOL_PINCTRL,
				 sizeof(*tx), 0, &t);

	tx = t->tx.buf;
	tx->identifier = identifier;
	tx->flags = SET_TYPE(cpu_to_le32(type));

	ret = scmi_do_xfer(handle, t);
	scmi_xfer_put(handle, t);

	return ret;
}

static int scmi_pinctrl_request_pin(const struct scmi_handle *handle, u32 pin)
{
	return scmi_pinctrl_request(handle, pin, PIN_TYPE);
}

static int scmi_pinctrl_free(const struct scmi_handle *handle, u32 identifier,
			     enum scmi_pinctrl_selector_type type)
{
	struct scmi_xfer *t;
	int ret;
	struct scmi_request_tx {
		__le32 identifier;
		__le32 flags;
	} *tx;

	if (!handle || type == FUNCTION_TYPE)
		return -EINVAL;

	ret = scmi_pinctrl_validate_id(handle, identifier, type);
	if (ret)
		return ret;

	ret = scmi_xfer_get_init(handle, PINCTRL_RELEASE, SCMI_PROTOCOL_PINCTRL,
				 sizeof(*tx), 0, &t);

	tx = t->tx.buf;
	tx->identifier = identifier;
	tx->flags = SET_TYPE(cpu_to_le32(type));

	ret = scmi_do_xfer(handle, t);
	scmi_xfer_put(handle, t);

	return ret;
}

static int scmi_pinctrl_free_pin(const struct scmi_handle *handle, u32 pin)
{
	return scmi_pinctrl_free(handle, pin, PIN_TYPE);
}


static int scmi_pinctrl_get_group_info(const struct scmi_handle *handle,
				       u32 selector,
				       struct scmi_group_info *group)
{
	int ret = 0;
	struct scmi_pinctrl_info *pi;

	if (!handle || !handle->pinctrl_priv || !group)
		return -EINVAL;

	pi = handle->pinctrl_priv;

	ret = scmi_pinctrl_attributes(handle, GROUP_TYPE, selector,
				      &group->name,
				      &group->nr_pins);
	if (ret)
		return ret;

	if (!group->nr_pins) {
		dev_err(handle->dev, "Group %d has 0 elements", selector);
		return -ENODATA;
	}

	group->group_pins = devm_kmalloc_array(handle->dev, group->nr_pins,
					       sizeof(*group->group_pins),
					       GFP_KERNEL);
	if (!group->group_pins) {
		ret = -ENOMEM;
		goto err;
	}

	ret = scmi_pinctrl_list_associations(handle, selector, GROUP_TYPE,
					     group->nr_pins, group->group_pins);
	if (ret)
		goto err_groups;

	group->present = true;
	return 0;

 err_groups:
	kfree(group->group_pins);
 err:
	kfree(group->name);
	return ret;
}

static int scmi_pinctrl_get_group_name(const struct scmi_handle *handle,
				       u32 selector, const char **name)
{
	int ret;
	struct scmi_pinctrl_info *pi;

	if (!handle || !handle->pinctrl_priv || !name)
		return -EINVAL;

	pi = handle->pinctrl_priv;

	if (selector > pi->nr_groups)
		return -EINVAL;

	if (!pi->groups[selector].present) {
		ret = scmi_pinctrl_get_group_info(handle, selector,
						  &pi->groups[selector]);
		if (ret)
			return ret;
	}

	*name = pi->groups[selector].name;

	return 0;
}

static int scmi_pinctrl_get_group_pins(const struct scmi_handle *handle,
				       u32 selector, const unsigned **pins,
				       unsigned *nr_pins)
{
	int ret;
	struct scmi_pinctrl_info *pi;

	if (!handle || !handle->pinctrl_priv || !pins || !nr_pins)
		return -EINVAL;

	pi = handle->pinctrl_priv;

	if (selector > pi->nr_groups)
		return -EINVAL;

	if (!pi->groups[selector].present) {
		ret = scmi_pinctrl_get_group_info(handle, selector,
						  &pi->groups[selector]);
		if (ret)
			return ret;
	}

	*pins = pi->groups[selector].group_pins;
	*nr_pins = pi->groups[selector].nr_pins;

	return ret;
}

static int scmi_pinctrl_get_function_info(const struct scmi_handle *handle,
					  u32 selector,
					  struct scmi_function_info *func)
{
	int ret = 0;
	struct scmi_pinctrl_info *pi;

	if (!handle || !handle->pinctrl_priv || !func)
		return -EINVAL;

	pi = handle->pinctrl_priv;

	ret = scmi_pinctrl_attributes(handle, FUNCTION_TYPE, selector,
				      &func->name,
				      &func->nr_groups);
	if (ret)
		return ret;

	if (!func->nr_groups) {
		dev_err(handle->dev, "Function %d has 0 elements", selector);
		return -ENODATA;
	}

	func->groups = devm_kmalloc_array(handle->dev, func->nr_groups,
					  sizeof(*func->groups),
					  GFP_KERNEL);
	if (!func->groups) {
		ret = -ENOMEM;
		goto err;
	}

	ret = scmi_pinctrl_list_associations(handle, selector, FUNCTION_TYPE,
					     func->nr_groups, func->groups);
	if (ret)
		goto err_funcs;

	func->present = true;
	return 0;

 err_funcs:
	kfree(func->groups);
 err:
	kfree(func->name);
	return ret;
}

static int scmi_pinctrl_get_function_name(const struct scmi_handle *handle,
					  u32 selector, const char **name)
{
	int ret;
	struct scmi_pinctrl_info *pi;

	if (!handle || !handle->pinctrl_priv || !name)
		return -EINVAL;

	pi = handle->pinctrl_priv;

	if (selector > pi->nr_functions)
		return -EINVAL;

	if (!pi->functions[selector].present) {
		ret = scmi_pinctrl_get_function_info(handle, selector,
						     &pi->functions[selector]);
		if (ret)
			return ret;
	}

	*name = pi->functions[selector].name;
	return 0;
}

static int scmi_pinctrl_get_function_groups(const struct scmi_handle *handle,
					    u32 selector, unsigned *nr_groups,
					    const unsigned **groups)
{
	int ret;
	struct scmi_pinctrl_info *pi;

	if (!handle || !handle->pinctrl_priv || !groups || !nr_groups)
		return -EINVAL;

	pi = handle->pinctrl_priv;

	if (selector > pi->nr_functions)
		return -EINVAL;

	if (!pi->functions[selector].present) {
		ret = scmi_pinctrl_get_function_info(handle, selector,
						     &pi->functions[selector]);
		if (ret)
			return ret;
	}

	*groups = pi->functions[selector].groups;
	*nr_groups = pi->functions[selector].nr_groups;

	return ret;
}

static int scmi_pinctrl_set_mux(const struct scmi_handle *handle, u32 selector,
				u32 group)
{
	return scmi_pinctrl_function_select(handle, group, GROUP_TYPE,
					    selector);
}

static int scmi_pinctrl_get_pin_info(const struct scmi_handle *handle,
				     u32 selector, struct scmi_pin_info *pin)
{
	int ret = 0;
	struct scmi_pinctrl_info *pi;
	unsigned n_elems;

	if (!handle || !handle->pinctrl_priv || !pin)
		return -EINVAL;

	pi = handle->pinctrl_priv;

	ret = scmi_pinctrl_attributes(handle, PIN_TYPE, selector,
				      &pin->name,
				      &n_elems);
	if (ret)
		return ret;

	if (n_elems != pi->nr_pins) {
		dev_err(handle->dev, "Wrong pin count expected %d has %d",
			pi->nr_pins, n_elems);
		return -ENODATA;
	}

	if (*(pin->name)== 0) {
		dev_err(handle->dev, "Pin name is empty");
		goto err;
	}

	pin->present = true;
	return 0;

 err:
	kfree(pin->name);
	return ret;
}

static int scmi_pinctrl_get_pin_name(const struct scmi_handle *handle, u32 selector,
				     const char **name)
{

	int ret;
	struct scmi_pinctrl_info *pi;

	if (!handle || !handle->pinctrl_priv || !name)
		return -EINVAL;

	pi = handle->pinctrl_priv;

	if (selector > pi->nr_pins)
		return -EINVAL;

	if (!pi->pins[selector].present) {
		ret = scmi_pinctrl_get_pin_info(handle, selector,
						&pi->pins[selector]);
		if (ret)
			return ret;
	}

	*name = pi->pins[selector].name;

	return 0;
}


static const struct scmi_pinctrl_ops pinctrl_ops = {
	.get_groups_count = scmi_pinctrl_get_groups_count,
	.get_group_name = scmi_pinctrl_get_group_name,
	.get_group_pins = scmi_pinctrl_get_group_pins,
	.get_functions_count = scmi_pinctrl_get_functions_count,
	.get_function_name = scmi_pinctrl_get_function_name,
	.get_function_groups = scmi_pinctrl_get_function_groups,
	.set_mux = scmi_pinctrl_set_mux,
	.get_pin_name = scmi_pinctrl_get_pin_name,
	.get_pins_count = scmi_pinctrl_get_pins_count,
	.get_config = scmi_pinctrl_get_config,
	.set_config = scmi_pinctrl_set_config,
	.get_config_group = scmi_pinctrl_get_config_group,
	.set_config_group = scmi_pinctrl_set_config_group,
	.request_pin = scmi_pinctrl_request_pin,
	.free_pin = scmi_pinctrl_free_pin
};

static int scmi_pinctrl_protocol_init(struct scmi_handle *handle)
{
	u32 version;
	struct scmi_pinctrl_info *pinfo;
	int ret;

	if (!handle)
		return -EINVAL;

	scmi_version_get(handle, SCMI_PROTOCOL_PINCTRL, &version);

	dev_dbg(handle->dev, "Pinctrl Version %d.%d\n",
		PROTOCOL_REV_MAJOR(version), PROTOCOL_REV_MINOR(version));

	pinfo = devm_kzalloc(handle->dev, sizeof(*pinfo), GFP_KERNEL);
	if (!pinfo)
		return -ENOMEM;

	ret = scmi_pinctrl_attributes_get(handle, pinfo);
	if (ret)
		goto free;

	pinfo->pins = devm_kmalloc_array(handle->dev, pinfo->nr_pins,
					 sizeof(*pinfo->pins),
					 GFP_KERNEL | __GFP_ZERO);
	if (!pinfo->pins) {
		ret = -ENOMEM;
		goto free;
	}

	pinfo->groups = devm_kmalloc_array(handle->dev, pinfo->nr_groups,
					   sizeof(*pinfo->groups),
					   GFP_KERNEL | __GFP_ZERO);
	if (!pinfo->groups) {
		ret = -ENOMEM;
		goto free;
	}

	pinfo->functions = devm_kmalloc_array(handle->dev, pinfo->nr_functions,
					      sizeof(*pinfo->functions),
					      GFP_KERNEL | __GFP_ZERO);
	if (!pinfo->functions) {
		ret = -ENOMEM;
		goto free;
	}

	pinfo->version = version;
	handle->pinctrl_ops = &pinctrl_ops;
	handle->pinctrl_priv = pinfo;

	return 0;
free:
	if (pinfo) {
		devm_kfree(handle->dev, pinfo->pins);
		devm_kfree(handle->dev, pinfo->functions);
		devm_kfree(handle->dev, pinfo->groups);
	}

	devm_kfree(handle->dev, pinfo);

	return ret;
}

DEFINE_SCMI_PROTOCOL_REGISTER_UNREGISTER(SCMI_PROTOCOL_PINCTRL, pinctrl)
