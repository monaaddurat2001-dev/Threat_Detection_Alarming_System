
def get_script_ranges(location_df):
    """Returns a dictionary mapping each script to its (min_interval, max_interval)"""
    script_ranges = {}
    for script in location_df['Script_Name'].unique():
        intervals = location_df[location_df['Script_Name'] == script]['Interval_ID']
        script_ranges[script] = (intervals.min(), intervals.max())
    return script_ranges
