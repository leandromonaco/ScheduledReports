using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace AutomatedTasks.ImportFileGenerator.Model
{
    public class AppSecItemComparer : IEqualityComparer<AppSecItem>
    {
        public bool Equals(AppSecItem x, AppSecItem y)
        {
            if (x.Category.Equals(y.Category))
            {
                return true;
            }
            return false;
        }

        public int GetHashCode([DisallowNull] AppSecItem obj)
        {
            return obj.Category.GetHashCode();
        }
    }
}
