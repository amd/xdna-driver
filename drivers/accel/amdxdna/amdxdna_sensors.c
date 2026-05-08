// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Advanced Micro Devices, Inc.
 */

#include "amdxdna_sensors.h"
#include <linux/hwmon.h>
#include <linux/uaccess.h>
#include <linux/units.h>

#if IS_ENABLED(CONFIG_AMD_PMF) && defined(HAVE_7_0_amd_pmf_get_npu_data)

#include <linux/amd-pmf-io.h>

int amdxdna_get_sensors(struct amdxdna_sensors *sensors)
{
	struct amd_pmf_npu_metrics npu_metrics = {};
	int ret;

#ifdef HAVE_7_2_amd_pmf_npu_metrics_npu_temp
	npu_metrics.npu_temp = AMDXDNA_INVALID_TEMPERATURE;
#endif
	ret = amd_pmf_get_npu_data(&npu_metrics);
	if (ret)
		return ret;

	sensors->npuclk_freq = npu_metrics.npuclk_freq;
	memcpy(sensors->npu_busy, npu_metrics.npu_busy,
	       min_t(size_t, sizeof(sensors->npu_busy), sizeof(npu_metrics.npu_busy)));
	sensors->npu_power = npu_metrics.npu_power;
	sensors->mpnpuclk_freq = npu_metrics.mpnpuclk_freq;
#ifdef HAVE_7_2_amd_pmf_npu_metrics_npu_temp
	sensors->npu_temp = npu_metrics.npu_temp;
#else
	sensors->npu_temp = AMDXDNA_INVALID_TEMPERATURE;
#endif
	return 0;
}

#else /* CONFIG_AMD_PMF && HAVE_7_0_amd_pmf_get_npu_data */

int amdxdna_get_sensors(struct amdxdna_sensors *sensors)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_AMD_PMF && HAVE_7_0_amd_pmf_get_npu_data */

int amdxdna_query_sensors(struct amdxdna_drm_get_info *args, u32 total_col)
{
	struct amdxdna_drm_query_sensor sensor = {};
	struct amdxdna_sensors npu_metrics;
	u32 sensors_count = 0, i;
	int ret;

	ret = amdxdna_get_sensors(&npu_metrics);
	if (ret)
		return ret;

	sensor.type = AMDXDNA_SENSOR_TYPE_POWER;
	sensor.input = npu_metrics.npu_power;
	sensor.unitm = -3;
	scnprintf(sensor.label, sizeof(sensor.label), "Total Power");
	scnprintf(sensor.units, sizeof(sensor.units), "mW");

	if (args->buffer_size < sizeof(sensor))
		goto out;

	if (copy_to_user(u64_to_user_ptr(args->buffer), &sensor, sizeof(sensor)))
		return -EFAULT;

	args->buffer_size -= sizeof(sensor);
	sensors_count++;

	if (npu_metrics.npu_temp != AMDXDNA_INVALID_TEMPERATURE) {
		memset(&sensor, 0, sizeof(sensor));
		sensor.type = AMDXDNA_SENSOR_TYPE_TEMPERATURE;
		sensor.input = npu_metrics.npu_temp;
		sensor.unitm = 0;
		scnprintf(sensor.label, sizeof(sensor.label), "Temperature");
		scnprintf(sensor.units, sizeof(sensor.units), "C");

		if (args->buffer_size < sizeof(sensor))
			goto out;

		if (copy_to_user(u64_to_user_ptr(args->buffer) + sensors_count * sizeof(sensor),
				 &sensor, sizeof(sensor)))
			return -EFAULT;

		args->buffer_size -= sizeof(sensor);
		sensors_count++;
	}

	for (i = 0; i < min_t(u32, total_col, AMDXDNA_NPU_MAX_PMF_COLUMNS); i++) {
		memset(&sensor, 0, sizeof(sensor));
		sensor.input = npu_metrics.npu_busy[i];
		sensor.type = AMDXDNA_SENSOR_TYPE_COLUMN_UTILIZATION;
		sensor.unitm = 0;
		scnprintf(sensor.label, sizeof(sensor.label), "Column %d Utilization", i);
		scnprintf(sensor.units, sizeof(sensor.units), "%%");

		if (args->buffer_size < sizeof(sensor))
			goto out;

		if (copy_to_user(u64_to_user_ptr(args->buffer) + sensors_count * sizeof(sensor),
				 &sensor, sizeof(sensor)))
			return -EFAULT;

		args->buffer_size -= sizeof(sensor);
		sensors_count++;
	}

out:
	args->buffer_size = sensors_count * sizeof(sensor);
	return 0;
}

static int
amdxdna_hwmon_read(struct device *dev, enum hwmon_sensor_types type,
		   u32 attr, int channel, long *val)
{
	struct amdxdna_sensors npu_metrics;
	int ret = -EOPNOTSUPP;

	switch (type) {
	case hwmon_temp:
		switch (attr) {
		case hwmon_temp_input:
			ret = amdxdna_get_sensors(&npu_metrics);
			if (ret)
				break;
			if (npu_metrics.npu_temp == AMDXDNA_INVALID_TEMPERATURE) {
				ret = -EOPNOTSUPP;
				break;
			}
			*val = npu_metrics.npu_temp * MILLIDEGREE_PER_DEGREE;
			break;
		default:
			break;
		}
		break;
	case hwmon_power:
		switch (attr) {
		case hwmon_power_input:
			ret = amdxdna_get_sensors(&npu_metrics);
			if (ret)
				break;
			*val = npu_metrics.npu_power * MICROWATT_PER_MILLIWATT;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return ret;
}

static int
amdxdna_hwmon_read_label(struct device *dev, enum hwmon_sensor_types type,
			 u32 attr, int channel, const char **str)
{
	switch (type) {
	case hwmon_temp:
		if (attr == hwmon_temp_label) {
			*str = "NPU_temperature";
			return 0;
		}
		break;
	case hwmon_power:
		if (attr == hwmon_power_label) {
			*str = "NPU_power";
			return 0;
		}
		break;
	default:
		break;
	}

	return -EOPNOTSUPP;
}

static umode_t
amdxdna_hwmon_is_visible(const void *data, enum hwmon_sensor_types type,
			 u32 attr, int channel)
{
	switch (type) {
	case hwmon_temp:
		switch (attr) {
		case hwmon_temp_input:
		case hwmon_temp_label:
			return 0444;
		default:
			return 0;
		}
	case hwmon_power:
		switch (attr) {
		case hwmon_power_input:
		case hwmon_power_label:
			return 0444;
		default:
			return 0;
		}
	default:
		return 0;
	}
}

static const struct hwmon_ops amdxdna_hwmon_ops = {
	.is_visible	= amdxdna_hwmon_is_visible,
	.read		= amdxdna_hwmon_read,
	.read_string	= amdxdna_hwmon_read_label,
};

static const struct hwmon_channel_info * const amdxdna_hwmon_info[] = {
	HWMON_CHANNEL_INFO(temp, HWMON_T_INPUT | HWMON_T_LABEL),
	HWMON_CHANNEL_INFO(power, HWMON_P_INPUT | HWMON_P_LABEL),
	NULL
};

static const struct hwmon_chip_info amdxdna_hwmon_chip_info = {
	.ops	= &amdxdna_hwmon_ops,
	.info	= amdxdna_hwmon_info,
};

void amdxdna_hwmon_init(struct amdxdna_dev *xdna)
{
	struct device *dev = xdna->ddev.dev;
	struct amdxdna_sensors npu_metrics;
	struct device *hwmon_dev;
	int ret;

	ret = amdxdna_get_sensors(&npu_metrics);
	if (ret) {
		XDNA_ERR(xdna, "No HWMON support due to missing PMF sensor support.");
		return;
	}

	hwmon_dev = devm_hwmon_device_register_with_info(dev, "amdxdna", NULL,
							 &amdxdna_hwmon_chip_info, NULL);
	if (IS_ERR(hwmon_dev))
		XDNA_ERR(xdna, "failed to register hwmon device: %ld", PTR_ERR(hwmon_dev));
}
