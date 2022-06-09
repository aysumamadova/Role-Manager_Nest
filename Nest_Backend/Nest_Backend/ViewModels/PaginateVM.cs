﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Nest_Backend.ViewModels
{
    public class PaginateVM<T>
    {
        public List <T> Items { get; set; }
        public int ActivePage { get; set; }
        public int PageCount { get; set; }
    }
}
