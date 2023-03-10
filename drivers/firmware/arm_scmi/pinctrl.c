// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) Pinctrl Protocol
 *
 * Copyright (C) 2021 EPAM.
 */

#define pr_fmt(fmt) "SCMI Notifications PINCTRL - " fmt

#include <linux/scmi_protocol.h>

#include "common.h"
#include "notify.h"

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
	bool has_name;
	char name[SCMI_MAX_STR_SIZE];
	unsigned group_pins[SCMI_PINCTRL_MAX_PINS_CNT];
	unsigned nr_pins;
};

struct scmi_function_info {
	bool has_name;
	char name[SCMI_MAX_STR_SIZE];
	u16 groups[SCMI_PINCTRL_MAX_GROUPS_CNT];
	u8 nr_groups;
};

struct scmi_pinctrl_info {
	u32 version;
	u16 nr_groups;
	u16 nr_functions;
	u16 nr_pins;
	struct scmi_group_info *groups;
	struct scmi_function_info *functions;
	u16 *pins;
};

#define SET_TYPE(x) ((x) & 0x3)

static int scmi_pinctrl_attributes_get(const struct scmi_handle *handle,
				     struct scmi_pinctrl_info *pi)
{
	int ret;
	struct scmi_xfer *t;
	struct scmi_msg_pinctrl_protocol_attributes {
#define PINS_NR(x) ((x) >> 16)
#define GROUPS_NR(x) ((x) & 0xffff)
		__le32 attributes_low;
#define FUNCTIONS_NR(x) ((x) & 0xffff)
		__le32 attributes_high;
	} *attr;

	ret = scmi_xfer_get_init(handle, PROTOCOL_ATTRIBUTES,
				 SCMI_PROTOCOL_PINCTRL, 0, sizeof(*attr), &t);
	if (ret)
		return ret;

	attr = t->rx.buf;

	ret = scmi_do_xfer(handle, t);
	if (!ret) {
		pi->nr_functions = le16_to_cpu(FUNCTIONS_NR(attr->attributes_high));
		pi->nr_groups = le16_to_cpu(GROUPS_NR(attr->attributes_low));
		pi->nr_pins = le16_to_cpu(PINS_NR(attr->attributes_low));
	}

	scmi_xfer_put(handle, t);
	return ret;
}

static int scmi_pinctrl_get_groups_count(const struct scmi_handle *handle)
{
	struct scmi_pinctrl_info *pi = handle->pinctrl_priv;

	return pi->nr_groups;
}

static int scmi_pinctrl_get_name(const struct scmi_handle *handle, u32 identifier,
					  enum scmi_pinctrl_selector_type type, char **name);

static int scmi_pinctrl_attributes(const struct scmi_handle *handle,
								   enum scmi_pinctrl_selector_type type,
								   u32 selector, char **name, u16 *n_elems)
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

   if (!EXT_NAME_FLAG(rx->attributes))
	   *name = kasprintf(GFP_KERNEL, "%s", rx->name);
   else
	   ret = scmi_pinctrl_get_name(handle, selector, type, name);
out:
	scmi_xfer_put(handle, t);
	return ret;
}

static int scmi_pinctrl_list_associations(const struct scmi_handle *handle, u32 selector,
										  enum scmi_pinctrl_selector_type type,
										  uint16_t size, uint16_t *array)
{ //done not tested
	struct scmi_xfer *t;
	struct scmi_pinctrl_list_assoc_tx {
		__le32 identifier;
#define SET_LIST_TYPE(attr, x) (((attr) & 0xFFFFFFFC) | (x & 0x2))
		__le32 flags;
		__le32 index;
	} *tx;
	struct scmi_pinctrl_list_assoc_rx {
#define REMAINING(x) ((x) >> 16)
#define RETURNED(x) ((x) & 0xFFF)
		__le32 flags;
		__le16 array[];
	} *rx;
	u16 tot_num_ret = 0, loop_num_ret;
	u16 remaining_num_ret;
	int ret, loop;

	ret = scmi_xfer_get_init(handle, PINCTRL_ATTRIBUTES,
				 SCMI_PROTOCOL_PINCTRL, sizeof(*tx),
				 sizeof(*rx), &t);
	if (ret)
		return ret;

	tx = t->tx.buf;
	rx = t->rx.buf;

	do {
		tx->identifier = cpu_to_le32(selector);
		tx->flags = SET_LIST_TYPE(tx->flags, cpu_to_le32(type));
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

			array[tot_num_ret + loop] = le16_to_cpu(rx->array[loop]);
		}

		tot_num_ret += loop_num_ret;

		scmi_reset_rx_to_maxsz(handle, t);
	} while (remaining_num_ret > 0);
out:
	scmi_xfer_put(handle, t);
    return ret;
}

//TODO amoi move to top
struct scmi_conf_tx {
	__le32 identifier;
#define SET_TYPE_BITS(attr, x) (((attr)&0xFFFFFCFF) | (x & 0x2) << 8)
#define SET_CONFIG(attr, x) ((attr) & 0xFF) | (x * 0xFF)
	__le32 attributes;
};

static int scmi_pinctrl_get_config(const struct scmi_handle *handle, u32 pin,
								   u32 *config)
{
	struct scmi_xfer *t;
	struct scmi_conf_tx *tx;
	__le32 *packed_config;
	int ret;
	//TODO amoi we support only for pin right now

	ret = scmi_xfer_get_init(handle, PINCTRL_CONFIG_GET, SCMI_PROTOCOL_PINCTRL,
				 sizeof(*tx), sizeof(*packed_config), &t);
	if (ret)
		return ret;

	tx = t->tx.buf;
	packed_config = t->rx.buf;
	tx->identifier = cpu_to_le32(pin);
	tx->attributes = SET_TYPE_BITS(tx->attributes, cpu_to_le32(PIN_TYPE));
	tx->attributes = SET_CONFIG(tx->attributes, cpu_to_le32(*config));

	ret = scmi_do_xfer(handle, t);

	if (!ret)
		*config = le32_to_cpu(*packed_config);

	scmi_xfer_put(handle, t);
	return ret;
}

static int scmi_pinctrl_set_config(const struct scmi_handle *handle, u32 pin,
								   enum scmi_pinctrl_selector_type type, u32 config)
{
	struct scmi_xfer *t;
	struct scmi_conf_tx *tx;
	int ret;
	//TODO amoi we support only for pin right now

	ret = scmi_xfer_get_init(handle, PINCTRL_CONFIG_SET, SCMI_PROTOCOL_PINCTRL,
				 sizeof(*tx), 0, &t);
	if (ret)
		return ret;

	tx = t->tx.buf;
	tx->identifier = cpu_to_le32(pin);
	tx->attributes = SET_TYPE_BITS(tx->attributes, cpu_to_le32(PIN_TYPE));
	tx->attributes = SET_CONFIG(tx->attributes, cpu_to_le32(config));

	ret = scmi_do_xfer(handle, t);

	scmi_xfer_put(handle, t);
	return ret;
}

static int scmi_pinctrl_function_select(const struct scmi_handle *handle, u32 identifier,
				   enum scmi_pinctrl_selector_type type,
				   u32 function_id)
{ //done not tested
	struct scmi_xfer *t;
	struct scmi_func_set_tx {
		__le32 identifier;
		__le32 function_id;
		__le32 flags;
	} *tx;
	int ret;

	ret = scmi_xfer_get_init(handle, PINCTRL_FUNCTION_SELECT, SCMI_PROTOCOL_PINCTRL,
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

static int scmi_pinctrl_request(const struct scmi_handle *handle, u32 identifier,
									enum scmi_pinctrl_selector_type type,
									u32 function_id)
{
	struct scmi_xfer *t;
	int ret;
	struct scmi_request_tx {
		__le32 identifier;
		__le32 function_id;
		__le32 flags;
	} *tx;

	ret = scmi_xfer_get_init(handle, PINCTRL_REQUEST, SCMI_PROTOCOL_PINCTRL,
				 sizeof(*tx), 0, &t);

	tx = t->tx.buf;
	tx->identifier = identifier;
	tx->function_id = function_id;
	tx->flags = SET_TYPE(cpu_to_le32(type));

	ret = scmi_do_xfer(handle, t);
	scmi_xfer_put(handle, t);

	return ret;
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

	ret = scmi_xfer_get_init(handle, PINCTRL_RELEASE, SCMI_PROTOCOL_PINCTRL,
				 sizeof(*tx), 0, &t);

	tx = t->tx.buf;
	tx->identifier = identifier;
	tx->flags = SET_TYPE(cpu_to_le32(type));

	ret = scmi_do_xfer(handle, t);
	scmi_xfer_put(handle, t);

	return ret;
}

static int scmi_pinctrl_get_name(const struct scmi_handle *handle, u32 identifier,
							 enum scmi_pinctrl_selector_type type, char **name)
{
	struct scmi_xfer *t;
	int ret;
	struct scmi_name_tx {
		__le32 identifier;
		__le32 flags;
	} *tx;
	struct scmi_name_rx {
		__le32 flags;
		u8 name[64];
	} *rx;

	ret = scmi_xfer_get_init(handle, PINCTRL_NAME_GET, SCMI_PROTOCOL_PINCTRL,
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
 out:
	scmi_xfer_put(handle, t);

	return ret;
}

static int scmi_pinctrl_get_group_name(const struct scmi_handle *handle,
					       u32 selector, const char **name)
{
	struct scmi_pinctrl_info *pi = handle->pinctrl_priv;

	if (selector > SCMI_PINCTRL_MAX_GROUPS_CNT)
		return -EINVAL;

	if (!pi->groups[selector].has_name) {
		snprintf(pi->groups[selector].name, SCMI_MAX_STR_SIZE, "%d", selector);
		pi->groups[selector].has_name = true;
	}

	*name = pi->groups[selector].name;

	return 0;
}
/////

static int scmi_pinctrl_get_group_pins(const struct scmi_handle *handle,
									   u32 selector, const unsigned **pins,
									   unsigned *nr_pins)
{
	struct scmi_pinctrl_info *pi = handle->pinctrl_priv;
	u16 *list;
	int loop, ret = 0;
	struct scmi_xfer *t;
	__le32 *num_ret;
	u16 tot_num_ret = 0, loop_num_ret;
	struct scmi_group_pins_tx {
		__le16 selector;
		__le16 skip;
	} *tx;

	if (selector > SCMI_PINCTRL_MAX_GROUPS_CNT)
		return -EINVAL;

	if (pi->groups[selector].nr_pins) {
		*nr_pins = pi->groups[selector].nr_pins;
		*pins = pi->groups[selector].group_pins;
		return 0;
	}

	ret = scmi_xfer_get_init(handle, GET_GROUP_PINS,
				 SCMI_PROTOCOL_PINCTRL, sizeof(*tx), 0, &t);
	if (ret)
		return ret;

	tx = t->tx.buf;
	num_ret = t->rx.buf;
	list = t->rx.buf + sizeof(*num_ret);

	do {
		/* Set the number of pins to be skipped/already read */
		tx->skip = cpu_to_le16(tot_num_ret);
		tx->selector = cpu_to_le16(selector);

		ret = scmi_do_xfer(handle, t);
		if (ret)
			break;

		loop_num_ret = le32_to_cpu(*num_ret);
		if (tot_num_ret + loop_num_ret > SCMI_PINCTRL_MAX_PINS_CNT) {
			dev_err(handle->dev, "No. of PINS > SCMI_PINCTRL_MAX_PINS_CNT");
			break;
		}

		for (loop = 0; loop < loop_num_ret; loop++) {
			pi->groups[selector].group_pins[tot_num_ret + loop] =
				le16_to_cpu(list[loop]);
		}

		tot_num_ret += loop_num_ret;

		scmi_reset_rx_to_maxsz(handle, t);
	} while (loop_num_ret);

	scmi_xfer_put(handle, t);
	pi->groups[selector].nr_pins = tot_num_ret;
	*pins = pi->groups[selector].group_pins;
	*nr_pins = pi->groups[selector].nr_pins;

	return ret;
}

static int scmi_pinctrl_get_functions_count(const struct scmi_handle *handle)
{
	struct scmi_pinctrl_info *pi = handle->pinctrl_priv;

	return pi->nr_functions;
}

static int scmi_pinctrl_get_function_name(const struct scmi_handle *handle,
								   u32 selector, const char **name)
{
	struct scmi_pinctrl_info *pi = handle->pinctrl_priv;

	if (selector >= pi->nr_functions)
		return -EINVAL;

	if (!pi->functions[selector].has_name) {
		snprintf(pi->functions[selector].name, SCMI_MAX_STR_SIZE,
				 "%d", selector);
		pi->functions[selector].has_name = true;
	}

	*name = pi->functions[selector].name;
	return 0;
}

static int scmi_pinctrl_get_function_groups(const struct scmi_handle *handle,
									 u32 selector, u32 *nr_groups,
									 const u16 **groups)
{
	struct scmi_pinctrl_info *pi = handle->pinctrl_priv;
	u16 *list;
	int loop, ret = 0;
	struct scmi_xfer *t;
	struct scmi_func_groups {
		__le16 selector;
		__le16 skip;
	} *tx;
	__le32 *num_ret;
	u16 tot_num_ret = 0, loop_num_ret;

	if (selector >= pi->nr_functions)
		return -EINVAL;

	if (pi->functions[selector].nr_groups) {
		*nr_groups = pi->functions[selector].nr_groups;
		*groups = pi->functions[selector].groups;
		return 0;
	}

	ret = scmi_xfer_get_init(handle, GET_FUNCTION_GROUPS,
				 SCMI_PROTOCOL_PINCTRL, sizeof(*tx), 0, &t);
	if (ret)
		return ret;

	tx = t->tx.buf;
	num_ret = t->rx.buf;
	list = t->rx.buf + sizeof(*num_ret);

	do {
		/* Set the number of pins to be skipped/already read */
		tx->skip = cpu_to_le16(tot_num_ret);
		tx->selector = cpu_to_le16(selector);

		ret = scmi_do_xfer(handle, t);
		if (ret)
			break;

		loop_num_ret = le32_to_cpu(*num_ret);
		if (tot_num_ret + loop_num_ret > SCMI_PINCTRL_MAX_GROUPS_CNT) {
			dev_err(handle->dev, "No. of PINS > SCMI_PINCTRL_MAX_GROUPS_CNT");
			break;
		}

		for (loop = 0; loop < loop_num_ret; loop++) {
			pi->functions[selector].groups[tot_num_ret + loop] = le16_to_cpu(list[loop]);
		}

		tot_num_ret += loop_num_ret;

		scmi_reset_rx_to_maxsz(handle, t);
	} while (loop_num_ret);

	scmi_xfer_put(handle, t);
	pi->functions[selector].nr_groups = tot_num_ret;
	*groups = pi->functions[selector].groups;
	*nr_groups = pi->functions[selector].nr_groups;

	return ret;
}

static int scmi_pinctrl_set_mux(const struct scmi_handle *handle, u32 selector,
						u32 group)
{
	struct scmi_xfer *t;
	struct scmi_mux_tx {
		__le16 function;
		__le16 group;
	} *tx;
	int ret;

	ret = scmi_xfer_get_init(handle, SET_MUX, SCMI_PROTOCOL_PINCTRL,
							 sizeof(*tx), 0, &t);
	if (ret)
		return ret;

	tx = t->tx.buf;
	tx->function = cpu_to_le16(selector);
	tx->group = cpu_to_le16(group);

	ret = scmi_do_xfer(handle, t);
	scmi_xfer_put(handle, t);

	return ret;
}

static int scmi_pinctrl_get_pins(const struct scmi_handle *handle, u32 *nr_pins,
						  const u16 **pins)
{
	struct scmi_pinctrl_info *pi = handle->pinctrl_priv;
	u16 *list;
	int loop, ret = 0;
	struct scmi_xfer *t;
	__le32 *num_skip, *num_ret;
	u32 tot_num_ret = 0, loop_num_ret;

	if (pi->nr_pins) {
		*nr_pins = pi->nr_pins;
		*pins = pi->pins;
		return 0;
	}

	ret = scmi_xfer_get_init(handle, GET_PINS,
				 SCMI_PROTOCOL_PINCTRL, sizeof(*num_skip), 0, &t);
	if (ret)
		return ret;

	num_skip = t->tx.buf;
	num_ret = t->rx.buf;
	list = t->rx.buf + sizeof(*num_ret);

	do {
		/* Set the number of pins to be skipped/already read */
		*num_skip = cpu_to_le32(tot_num_ret);

		ret = scmi_do_xfer(handle, t);
		if (ret)
			break;

		loop_num_ret = le32_to_cpu(*num_ret);
		if (tot_num_ret + loop_num_ret > SCMI_PINCTRL_MAX_PINS_CNT) {
			dev_err(handle->dev, "No. of PINS > SCMI_PINCTRL_MAX_PINS_CNT");
			break;
		}

		for (loop = 0; loop < loop_num_ret; loop++) {
			pi->pins[tot_num_ret + loop] = le16_to_cpu(list[loop]);
		}

		tot_num_ret += loop_num_ret;

		scmi_reset_rx_to_maxsz(handle, t);
	} while (loop_num_ret);

	scmi_xfer_put(handle, t);
	pi->nr_pins = tot_num_ret;
	*pins = pi->pins;
	*nr_pins = pi->nr_pins;

	return ret;
}

static int scmi_pinctrl_set_config(const struct scmi_handle *handle, u32 pin,
				  u32 config)
{
	struct scmi_xfer *t;
	struct scmi_conf_tx {
		__le32 pin;
		__le32 config;
	} *tx;
	int ret;

	ret = scmi_xfer_get_init(handle, SET_CONFIG, SCMI_PROTOCOL_PINCTRL,
							 sizeof(*tx), 0, &t);
	if (ret)
		return ret;

	tx = t->tx.buf;
	tx->pin = cpu_to_le32(pin);
	tx->config = cpu_to_le32(config);
	ret = scmi_do_xfer(handle, t);

	scmi_xfer_put(handle, t);
	return ret;
}

static int scmi_pinctrl_get_config_group(const struct scmi_handle *handle,
										 u32 group, u32 *config)
{
	struct scmi_xfer *t;
	struct scmi_conf_tx {
		__le32 group;
		__le32 config;
	} *tx;
	__le32 *packed_config;
	int ret;

	ret = scmi_xfer_get_init(handle, GET_CONFIG_GROUP, SCMI_PROTOCOL_PINCTRL,
							 sizeof(*tx), sizeof(*packed_config), &t);
	if (ret)
		return ret;

	tx = t->tx.buf;
	packed_config = t->rx.buf;
	tx->group = cpu_to_le32(group);
	tx->config = cpu_to_le32(*config);
	ret = scmi_do_xfer(handle, t);

	if (!ret)
		*config = le32_to_cpu(*packed_config);

	scmi_xfer_put(handle, t);
	return ret;
}

static int scmi_pinctrl_set_config_group(const struct scmi_handle *handle,
										 u32 group, u32 config)
{
	struct scmi_xfer *t;
	struct scmi_conf_tx {
		__le32 group;
		__le32 config;
	} *tx;
	int ret;

	ret = scmi_xfer_get_init(handle, SET_CONFIG_GROUP, SCMI_PROTOCOL_PINCTRL,
							 sizeof(*tx), 0, &t);
	if (ret)
		return ret;

	tx = t->tx.buf;
	tx->group = cpu_to_le32(group);
	tx->config = cpu_to_le32(config);
	ret = scmi_do_xfer(handle, t);

	scmi_xfer_put(handle, t);
	return ret;
}

static const struct scmi_pinctrl_ops pinctrl_ops = {
	.get_groups_count = scmi_pinctrl_get_groups_count, //+
	.get_group_name = scmi_pinctrl_get_group_name,
	.get_group_pins = scmi_pinctrl_get_group_pins,
	.get_functions_count = scmi_pinctrl_get_functions_count,
	.get_function_name = scmi_pinctrl_get_function_name,
	.get_function_groups = scmi_pinctrl_get_function_groups,
	.set_mux = scmi_pinctrl_set_mux,
	.get_pins = scmi_pinctrl_get_pins,
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
	int ret, i;

	scmi_version_get(handle, SCMI_PROTOCOL_PINCTRL, &version);

	dev_dbg(handle->dev, "Pinctrl Version %d.%d\n",
		PROTOCOL_REV_MAJOR(version), PROTOCOL_REV_MINOR(version));

	pinfo = devm_kzalloc(handle->dev, sizeof(*pinfo), GFP_KERNEL);
	if (!pinfo)
		return -ENOMEM;

	ret = scmi_pinctrl_attributes_get(handle, pinfo);
	if (ret)
		goto free;

	pinfo->pins = devm_kcalloc(handle->dev, pinfo->nr_pins,
				     sizeof(*pinfo->pins), GFP_KERNEL);
	if (!pinfo->pins) {
		ret = -ENOMEM;
		goto free;
	}

	pinfo->groups = devm_kcalloc(handle->dev, pinfo->nr_groups,
								 sizeof(*pinfo->groups), GFP_KERNEL);
	if (!pinfo->groups) {
		ret = -ENOMEM;
		goto free;
	}

	pinfo->functions = devm_kcalloc(handle->dev, pinfo->nr_functions,
								 sizeof(*pinfo->functions), GFP_KERNEL);
	if (!pinfo->functions) {
		ret = -ENOMEM;
		goto free;
	}

	// - get it from get_pins
	// go through groups
	for (i = 0; i < pinfo->nr_groups; i++) {
		ret = scmi_pinctrl_attributes(handle, type, GROUP_TYPE,
					      char **name, int *n_elems)
			pinfo->groups[i].name
			pinfo->nr_groups = n_elems;
	}
	// go through functions

	pinfo->version = version;
	handle->pinctrl_ops = &pinctrl_ops;
	handle->pinctrl_priv = pinfo;

	return 0;
free:
	if (pinfo) {
		if (pinfo->pins)
			devm_kfree(handle->dev, pinfo->pins);

		if (pinfo->functions)
			devm_kfree(handle->dev,pinfo->functions);

		if (pinfo->groups)
			devm_kfree(handle->dev,pinfo->groups);

		devm_kfree(handle->dev,pinfo);
	}

	return ret;
}

DEFINE_SCMI_PROTOCOL_REGISTER_UNREGISTER(SCMI_PROTOCOL_PINCTRL, pinctrl)
