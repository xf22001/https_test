

/*================================================================
 *   Copyright (C) 2017年08月18日 肖飞 All rights reserved
 *
 *   文件名称：memory.c
 *   创 建 者：肖飞

 *   创建日期：2017年08月18日 星期五 09时23分55秒
 *   修改日期：2017年08月18日 星期五 10时31分54秒
 *   描    述：
 *
 *================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "list.h"

#define myprintf(fmt, args...) printf(fmt, ## args)

typedef struct _mem_info {
	int initilized;
	unsigned long long total_count;
	unsigned long long total_size;
	unsigned long long total_size_max;
	struct list_head head; //need to initilized
} mem_info_t;

typedef struct _node {
	struct list_head list;

	unsigned long long size;
	void *ptr;
} node_t;

mem_info_t mem_info = {0};

int init_mem_info()
{
	int ret = 0;
	mem_info.initilized = 1;
	mem_info.total_count = 0;
	mem_info.total_size = 0;
	mem_info.total_size_max = 0;
	INIT_LIST_HEAD(&mem_info.head);
	//myprintf("mem_info.head:%p\n", &mem_info.head);
	return ret;
}

int account_malloc(int size, void *ptr)
{
	int ret = 0;

	node_t *node = (node_t *)malloc(sizeof(node_t));

	if(node == NULL) {
		ret = -1;
		return ret;
	}

	if(mem_info.initilized == 0) {
		init_mem_info();
	}

	mem_info.total_count += 1;
	mem_info.total_size += size;

	node->ptr = ptr;
	node->size = size;
	list_add_tail(&node->list, &mem_info.head);

	if(mem_info.total_size > mem_info.total_size_max) {
		mem_info.total_size_max = mem_info.total_size;
		myprintf("[peak-value]:mem_info.total_count:%llu, mem_info.total_size:%llu\n", mem_info.total_count, mem_info.total_size);
	}

	return ret;
}

int account_free(void *ptr)
{
	int ret = 0;
	node_t *node = NULL;
	bool found = false;

	if(mem_info.initilized == 0) {
		init_mem_info();
	}

	if(list_empty(&mem_info.head)) {
		myprintf("meminfo:no meminfo!\n");
		ret = -1;
		return ret;
	}

	list_for_each_entry(node, &mem_info.head, node_t, list) {
		if(node->ptr == ptr) {
			found = true;
			break;
		}
	}

	if(!found) {
		myprintf("meminfo:not found mem block %p!\n", ptr);
		ret = -1;
		return ret;
	}

	mem_info.total_count -= 1;
	mem_info.total_size -= node->size;

	list_del(&node->list);
	free(node);

	return ret;
}

void *malloc_1(int size)
{
	int ret = 0;
	void *ptr = NULL;

	ptr = malloc(size);

	if(ptr == NULL) {
		return ptr;
	}

	ret = account_malloc(size, ptr);

	if(ret != 0) {
		free(ptr);
		ptr = NULL;
		return ptr;
	}

	return ptr;
}

void *calloc_1(size_t nmemb, size_t size)
{
	int ret = 0;
	void *ptr = NULL;

	ptr = calloc(nmemb, size);

	if(ptr == NULL) {
		return ptr;
	}

	ret = account_malloc(nmemb * size, ptr);

	if(ret != 0) {
		free(ptr);
		ptr = NULL;
		return ptr;
	}

	return ptr;
}

void free_1(void *ptr)
{
	int ret = 0;

	ret = account_free(ptr);

	if(ret != 0) {
		return;
	}

	free(ptr);
}

void *realloc_1(void *ptr, size_t size)
{
	int ret = 0;
	void *new_ptr = NULL;

	new_ptr = realloc(ptr, size);

	if(new_ptr == NULL) {
		return new_ptr;
	}

	ret = account_free(ptr);

	ret = account_malloc(size, new_ptr);

	if(ret != 0) {
		free(new_ptr);
		new_ptr = NULL;
		return new_ptr;
	}

	return new_ptr;
}

int p_mem_info()
{
	int ret = 0;

	node_t *node = NULL;
	unsigned long long total_count = 0;
	unsigned long long total_size = 0;

	if(mem_info.initilized == 0) {
		init_mem_info();
	}

	list_for_each_entry(node, &mem_info.head, node_t, list) {
		total_count += 1;
		total_size += node->size;
		myprintf("[%llu]:%p %llu\n", total_count, node->ptr, node->size);
	}

	myprintf("total_count:%llu, total_size:%llu\n", total_count, total_size);

	myprintf("mem_info.total_count:%llu, mem_info.total_size:%llu\n", mem_info.total_count, mem_info.total_size);
	return ret;
}

/*
int main(int argc, char **args)
{
	int ret = 0;
	void *p1, *p2, *p3 = NULL, *p4, *p5 = NULL;

	myprintf("=================free p5\n");
	free_1(p5);
	p_mem_info();

	myprintf("=================alloc p1 1\n");
	p1 = malloc_1(1);
	p_mem_info();

	myprintf("=================calloc p2 2, 2\n");
	p2 = calloc_1(2, 2);
	p_mem_info();

	myprintf("=================realloc p3 3\n");
	p3 = realloc_1(p3, 3);
	p_mem_info();

	myprintf("=================realloc p3 7\n");
	myprintf("p3:%p\n", p3);
	p3 = realloc_1(p3, 7);
	p_mem_info();

	myprintf("=================realloc p3 9\n");
	p3 = realloc_1(p3, 9);
	p_mem_info();

	myprintf("=================alloc p4 4\n");
	p4 = malloc_1(4);
	p_mem_info();

	myprintf("=================free p1\n");
	free_1(p1);
	p1 = NULL;
	p_mem_info();

	myprintf("=================free p2\n");
	free_1(p2);
	p2 = NULL;
	p_mem_info();

	myprintf("=================free p3\n");
	free_1(p3);
	p3 = NULL;
	p_mem_info();

	myprintf("=================free p4\n");
	free_1(p4);
	p4 = NULL;
	p_mem_info();

	return ret;
}
*/
