using System;
using System.Collections.Generic;
using System.Configuration;

namespace Security.ClaimAttributes.Configuration
{
    public static class GroupConfiguration
    {
        private const string SectionName = "adGroups";

        static GroupConfiguration()
        {
            GroupConfig = (GroupConfigSection)ConfigurationManager.GetSection(SectionName) ?? new GroupConfigSection();//Do we need this?
        }

        private static GroupConfigSection GroupConfig { get; set; }

        public static IList<GroupConfigElement> Groups
        {
            get
            {
                return GroupConfig.Groups as IList<GroupConfigElement>;
            }
        }
    }

    public class GroupConfigElement : ConfigurationElement
    {
        [ConfigurationProperty("name", IsKey = true, IsRequired = false)]
        public string Name
        {
            get
            {
                return (string)base["name"];
            }
            set
            {
                base["name"] = value;
            }
        }

        [ConfigurationProperty("sid", IsKey = false, IsRequired = true)]
        internal string Sid
        {
            get
            {
                return (string)base["sid"];
            }
            set
            {
                base["sid"] = value;
            }
        }
    }

    public class GroupConfigElementCollection : ConfigurationElementCollection, IList<GroupConfigElement>
    {
        public override ConfigurationElementCollectionType CollectionType
        {
            get
            {
                return ConfigurationElementCollectionType.AddRemoveClearMap;
            }
        }

        public new bool IsReadOnly
        {
            get
            {
                return IsReadOnly();
            }
        }

        public GroupConfigElement this[int index]
        {
            get
            {
                return (GroupConfigElement)BaseGet(index);
            }
            set
            {
                if (BaseGet(index) != null)
                    BaseRemoveAt(index);
                BaseAdd(index, value);
            }
        }

        new public GroupConfigElement this[string key]
        {
            get
            {
                return (GroupConfigElement)BaseGet(key);
            }
        }

        public void Add(GroupConfigElement SecurityConfigElement)
        {
            BaseAdd(SecurityConfigElement, true);
        }

        public void Clear()
        {
            BaseClear();
        }

        public bool Contains(GroupConfigElement element)
        {
            return IndexOf(element) > -1;
        }

        public void CopyTo(GroupConfigElement[] array, int arrayIndex)
        {
            base.CopyTo(array, arrayIndex);
        }

        public new IEnumerator<GroupConfigElement> GetEnumerator()
        {
            for (var i = 0; i < Count; i++)
            {
                yield return BaseGet(i) as GroupConfigElement;
            }
        }

        bool ICollection<GroupConfigElement>.Remove(GroupConfigElement element)
        {
            BaseRemove(GetElementKey(element));
            return true;
        }

        public int IndexOf(GroupConfigElement element)
        {
            return BaseIndexOf(element);
        }

        public void Insert(int index, GroupConfigElement element)
        {
            throw new NotImplementedException();
        }

        public void Remove(GroupConfigElement element)
        {
            if (BaseIndexOf(element) >= 0)
                BaseRemove(element.Name);
        }

        public void Remove(string name)
        {
            BaseRemove(name);
        }

        public void RemoveAt(int index)
        {
            BaseRemoveAt(index);
        }

        protected override void BaseAdd(ConfigurationElement element)
        {
            base.BaseAdd(element, false);
        }

        protected override ConfigurationElement CreateNewElement()
        {
            return new GroupConfigElement();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            return ((GroupConfigElement)element).Name;
        }
    }

    public class GroupConfigSection : ConfigurationSection
    {
        [ConfigurationProperty("groups", IsDefaultCollection = false)]
        [ConfigurationCollection(typeof(GroupConfigElementCollection), AddItemName = "add", ClearItemsName = "clear", RemoveItemName = "remove")]
        public GroupConfigElementCollection Groups
        {
            get
            {
                return (GroupConfigElementCollection)base["groups"];
            }
        }
    }
}
