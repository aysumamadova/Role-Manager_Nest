#pragma checksum "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "d017a4e778981d3fdd999dc5baecf9128dd9ce69"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Shared_Components_Product_Default), @"mvc.1.0.view", @"/Views/Shared/Components/Product/Default.cshtml")]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#nullable restore
#line 1 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\_ViewImports.cshtml"
using Nest_Backend;

#line default
#line hidden
#nullable disable
#nullable restore
#line 2 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\_ViewImports.cshtml"
using Nest_Backend.Models;

#line default
#line hidden
#nullable disable
#nullable restore
#line 3 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\_ViewImports.cshtml"
using Nest_Backend.ViewModels;

#line default
#line hidden
#nullable disable
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"d017a4e778981d3fdd999dc5baecf9128dd9ce69", @"/Views/Shared/Components/Product/Default.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"57478d0b789b0ec658c37f7590456baedb99b5f6", @"/Views/_ViewImports.cshtml")]
    public class Views_Shared_Components_Product_Default : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<PaginateVM<Product>>
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("asp-action", "Details", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_1 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("method", "post", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_2 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("asp-controller", "Product", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_3 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("asp-action", "AddBasket", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_4 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("class", new global::Microsoft.AspNetCore.Html.HtmlString("add-cart"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_5 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("class", new global::Microsoft.AspNetCore.Html.HtmlString("page-link"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_6 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("asp-action", "Index", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        #line hidden
        #pragma warning disable 0649
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperExecutionContext __tagHelperExecutionContext;
        #pragma warning restore 0649
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner __tagHelperRunner = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner();
        #pragma warning disable 0169
        private string __tagHelperStringValueBuffer;
        #pragma warning restore 0169
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __backed__tagHelperScopeManager = null;
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __tagHelperScopeManager
        {
            get
            {
                if (__backed__tagHelperScopeManager == null)
                {
                    __backed__tagHelperScopeManager = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager(StartTagHelperWritingScope, EndTagHelperWritingScope);
                }
                return __backed__tagHelperScopeManager;
            }
        }
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.AnchorTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper;
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper;
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper;
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
#nullable restore
#line 2 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml"
 foreach (var item in Model.Items)
{

#line default
#line hidden
#nullable disable
            WriteLiteral(@"    <div class=""col-lg-1-5 col-md-4 col-12 col-sm-6"">
        <div class=""product-cart-wrap mb-30"">
            <div class=""product-img-action-wrap"">
                <div class=""product-img product-img-zoom"">
                    <a href=""shop-product-right.html"">
                        <img class=""default-img"" width=""190""");
            BeginWriteAttribute("src", " src=\"", 396, "\"", 479, 2);
            WriteAttributeValue("", 402, "assets/imgs/shop/", 402, 17, true);
#nullable restore
#line 9 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml"
WriteAttributeValue("", 419, item.ProductImgs.FirstOrDefault(pi=>pi.IsFront==true).Image, 419, 60, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            BeginWriteAttribute("alt", " alt=\"", 480, "\"", 486, 0);
            EndWriteAttribute();
            WriteLiteral(" />\r\n                        <img class=\"hover-img\" width=\"190\"");
            BeginWriteAttribute("src", " src=\"", 550, "\"", 632, 2);
            WriteAttributeValue("", 556, "assets/imgs/shop/", 556, 17, true);
#nullable restore
#line 10 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml"
WriteAttributeValue("", 573, item.ProductImgs.FirstOrDefault(pi=>pi.IsBack==true).Image, 573, 59, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            BeginWriteAttribute("alt", " alt=\"", 633, "\"", 639, 0);
            EndWriteAttribute();
            WriteLiteral(@" />
                    </a>
                </div>
                <div class=""product-action-1"">
                    <a aria-label=""Add To Wishlist"" class=""action-btn"" href=""shop-wishlist.html""><i class=""fi-rs-heart""></i></a>
                    <a aria-label=""Quick view"" class=""action-btn"" data-bs-toggle=""modal"" data-bs-target=""#quickViewModal""><i class=""fi-rs-eye""></i></a>
                </div>
                <div class=""product-badges product-badges-position product-badges-mrg"">
");
#nullable restore
#line 18 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml"
                     if (item.StockCount == 0)
                    {

#line default
#line hidden
#nullable disable
            WriteLiteral("                        <span class=\"hot\">Bitdi</span>\r\n");
#nullable restore
#line 21 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml"
                    }

#line default
#line hidden
#nullable disable
            WriteLiteral("                </div>\r\n            </div>\r\n            <div class=\"product-content-wrap\">\r\n                <div class=\"product-category\">\r\n                    <a href=\"shop-grid-right.html\">");
#nullable restore
#line 26 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml"
                                              Write(item.Categories.Name);

#line default
#line hidden
#nullable disable
            WriteLiteral("</a>\r\n                </div>\r\n                <h2>");
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("a", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "d017a4e778981d3fdd999dc5baecf9128dd9ce699537", async() => {
#nullable restore
#line 28 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml"
                                                               Write(item.Name);

#line default
#line hidden
#nullable disable
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.AnchorTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper.Action = (string)__tagHelperAttribute_0.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_0);
            if (__Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper.RouteValues == null)
            {
                throw new InvalidOperationException(InvalidTagHelperIndexerAssignment("asp-route-id", "Microsoft.AspNetCore.Mvc.TagHelpers.AnchorTagHelper", "RouteValues"));
            }
            BeginWriteTagHelperAttribute();
#nullable restore
#line 28 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml"
                                              WriteLiteral(item.Id);

#line default
#line hidden
#nullable disable
            __tagHelperStringValueBuffer = EndWriteTagHelperAttribute();
            __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper.RouteValues["id"] = __tagHelperStringValueBuffer;
            __tagHelperExecutionContext.AddTagHelperAttribute("asp-route-id", __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper.RouteValues["id"], global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            WriteLiteral("</h2>\r\n                <div class=\"product-rate-cover\">\r\n                    <div class=\"product-rate d-inline-block\">\r\n                        <div class=\"product-rating\"");
            BeginWriteAttribute("style", " style=\"", 1784, "\"", 1818, 3);
            WriteAttributeValue("", 1792, "width:", 1792, 6, true);
#nullable restore
#line 31 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml"
WriteAttributeValue(" ", 1798, item.Raiting*20, 1799, 18, false);

#line default
#line hidden
#nullable disable
            WriteAttributeValue("", 1817, "%", 1817, 1, true);
            EndWriteAttribute();
            WriteLiteral("></div>\r\n                    </div>\r\n                    <span class=\"font-small ml-5 text-muted\"> (");
#nullable restore
#line 33 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml"
                                                          Write(item.Raiting);

#line default
#line hidden
#nullable disable
            WriteLiteral(")</span>\r\n                </div>\r\n");
            WriteLiteral("                <div class=\"product-card-bottom\">\r\n                    <div class=\"product-price\">\r\n                        <span>$");
#nullable restore
#line 40 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml"
                          Write(item.Price);

#line default
#line hidden
#nullable disable
            WriteLiteral("</span>\r\n");
            WriteLiteral("                    </div>\r\n                    ");
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("form", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "d017a4e778981d3fdd999dc5baecf9128dd9ce6913683", async() => {
                WriteLiteral("\r\n                        <button type=\"submit\" class=\"add\"><i class=\"fi-rs-shopping-cart mr-5\"></i>Add </button>\r\n                    ");
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.Method = (string)__tagHelperAttribute_1.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_1);
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.Controller = (string)__tagHelperAttribute_2.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_2);
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.Action = (string)__tagHelperAttribute_3.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_3);
            if (__Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.RouteValues == null)
            {
                throw new InvalidOperationException(InvalidTagHelperIndexerAssignment("asp-route-id", "Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper", "RouteValues"));
            }
            BeginWriteTagHelperAttribute();
#nullable restore
#line 43 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml"
                                                                                          WriteLiteral(item.Id);

#line default
#line hidden
#nullable disable
            __tagHelperStringValueBuffer = EndWriteTagHelperAttribute();
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.RouteValues["id"] = __tagHelperStringValueBuffer;
            __tagHelperExecutionContext.AddTagHelperAttribute("asp-route-id", __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.RouteValues["id"], global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_4);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            WriteLiteral("\r\n                </div>\r\n            </div>\r\n        </div>\r\n    </div>\r\n");
#nullable restore
#line 50 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml"
}

#line default
#line hidden
#nullable disable
            WriteLiteral(@"<div class=""pagination-area mt-20 mb-20"">
    <nav aria-label=""Page navigation example"">
        <ul class=""pagination justify-content-start"">
            <li class=""page-item"">
                <a class=""page-link"" href=""#""><i class=""fi-rs-arrow-small-left""></i></a>
            </li>
");
#nullable restore
#line 57 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml"
             for (int i = 1; i <= Model.PageCount; i++)
            {


#line default
#line hidden
#nullable disable
            WriteLiteral("            <li");
            BeginWriteAttribute("class", " class=\"", 3110, "\"", 3161, 2);
            WriteAttributeValue("", 3118, "page-item", 3118, 9, true);
#nullable restore
#line 60 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml"
WriteAttributeValue("", 3127, Model.ActivePage==i?"active":"", 3127, 34, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            WriteLiteral(">");
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("a", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "d017a4e778981d3fdd999dc5baecf9128dd9ce6918252", async() => {
#nullable restore
#line 60 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml"
                                                                                                                                                    Write(i);

#line default
#line hidden
#nullable disable
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.AnchorTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_5);
            __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper.Controller = (string)__tagHelperAttribute_2.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_2);
            __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper.Action = (string)__tagHelperAttribute_6.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_6);
            if (__Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper.RouteValues == null)
            {
                throw new InvalidOperationException(InvalidTagHelperIndexerAssignment("asp-route-page", "Microsoft.AspNetCore.Mvc.TagHelpers.AnchorTagHelper", "RouteValues"));
            }
            BeginWriteTagHelperAttribute();
#nullable restore
#line 60 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml"
                                                                                                                                         WriteLiteral(i);

#line default
#line hidden
#nullable disable
            __tagHelperStringValueBuffer = EndWriteTagHelperAttribute();
            __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper.RouteValues["page"] = __tagHelperStringValueBuffer;
            __tagHelperExecutionContext.AddTagHelperAttribute("asp-route-page", __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper.RouteValues["page"], global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            WriteLiteral("</li>\r\n");
#nullable restore
#line 61 "C:\Users\tu7tw2d21\Desktop\Registration_Nest\Nest_Backend\Nest_Backend\Views\Shared\Components\Product\Default.cshtml"
            }

#line default
#line hidden
#nullable disable
            WriteLiteral("            <li class=\"page-item\">\r\n                <a class=\"page-link\" href=\"#\"><i class=\"fi-rs-arrow-small-right\"></i></a>\r\n            </li>\r\n        </ul>\r\n    </nav>\r\n</div>\r\n");
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<PaginateVM<Product>> Html { get; private set; }
    }
}
#pragma warning restore 1591
