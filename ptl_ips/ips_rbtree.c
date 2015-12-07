/*

  This file is provided under a dual BSD/GPLv2 license.  When using or
  redistributing this file, you may do so under either license.

  GPL LICENSE SUMMARY

  Copyright(c) 2015 Intel Corporation.

  This program is free software; you can redistribute it and/or modify
  it under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  Contact Information:
  Intel Corporation, www.intel.com

  BSD LICENSE

  Copyright(c) 2015 Intel Corporation.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

/* Copyright (c) 2003-2015 Intel Corporation. All rights reserved. */

/*
 * Abstract:
 *	Implementation of quick map, a binary tree where the caller always provides
 *	all necessary storage.
 *
 * Environment:
 *	All
 *
 * $Revision$
 */


/*****************************************************************************
*
* Map
*
* Map is an associative array.  By providing a key, the caller can retrieve
* an object from the map.  All objects in the map have an associated key,
* as specified by the caller when the object was inserted into the map.
* In addition to random access, the caller can traverse the map much like
* a linked list, either forwards from the first object or backwards from
* the last object.  The objects in the map are always traversed in
* order since the nodes are stored sorted.
*
* This implementation of Map uses a red black tree verified against
* Cormen-Leiserson-Rivest text, McGraw-Hill Edition, fourteenth
* printing, 1994.
*
*****************************************************************************/


#include "psm_user.h"
#include "ips_tidcache.h"


/******************************************************************************
*******************************************************************************
**************													   ************
**************			 IMPLEMENTATION OF QUICK MAP			   ************
**************													   ************
*******************************************************************************
******************************************************************************/

/*
 * Get the root.
 */
static inline cl_map_item_t*
__cl_map_root(
	IN	const cl_qmap_t* const	p_map )
{
	ASSERT( p_map );
	return( p_map->root->p_left );
}


/*
 * Returns whether a given item is on the left of its parent.
 */
static int
__cl_map_is_left_child(
	IN	const cl_map_item_t* const	p_item )
{
	ASSERT( p_item );
	ASSERT( p_item->p_up );
	ASSERT( p_item->p_up != p_item );

	return( p_item->p_up->p_left == p_item );
}


/*
 * Retrieve the pointer to the parent's pointer to an item.
 */
static cl_map_item_t**
__cl_map_get_parent_ptr_to_item(
	IN	cl_map_item_t* const	p_item )
{
	ASSERT( p_item );
	ASSERT( p_item->p_up );
	ASSERT( p_item->p_up != p_item );

	if( __cl_map_is_left_child( p_item ) )
		return( &p_item->p_up->p_left );

	ASSERT( p_item->p_up->p_right == p_item );
	return( &p_item->p_up->p_right );
}


/*
 * Rotate a node to the left.  This rotation affects the least number of links
 * between nodes and brings the level of C up by one while increasing the depth
 * of A one.  Note that the links to/from W, X, Y, and Z are not affected.
 *
 *	    R				      R
 *	    |				      |
 *	    A				      C
 *	  /   \			        /   \
 *	W       C			  A       Z
 *	       / \			 / \
 *	      B   Z			W   B
 *	     / \			   / \
 *	    X   Y			  X   Y
 */
static void
__cl_map_rot_left(
	IN	cl_qmap_t* const		p_map,
	IN	cl_map_item_t* const	p_item )
{
	cl_map_item_t	**pp_root;

	ASSERT( p_map );
	ASSERT( p_item );
	ASSERT( p_item->p_right != p_map->nil_item );

	pp_root = __cl_map_get_parent_ptr_to_item( p_item );

	/* Point R to C instead of A. */
	*pp_root = p_item->p_right;
	/* Set C's parent to R. */
	(*pp_root)->p_up = p_item->p_up;

	/* Set A's right to B */
	p_item->p_right = (*pp_root)->p_left;
	/*
	 * Set B's parent to A.  We trap for B being NIL since the
	 * caller may depend on NIL not changing.
	 */
	if( (*pp_root)->p_left != p_map->nil_item )
		(*pp_root)->p_left->p_up = p_item;

	/* Set C's left to A. */
	(*pp_root)->p_left = p_item;
	/* Set A's parent to C. */
	p_item->p_up = *pp_root;
}


/*
 * Rotate a node to the right.  This rotation affects the least number of links
 * between nodes and brings the level of A up by one while increasing the depth
 * of C one.  Note that the links to/from W, X, Y, and Z are not affected.
 *
 *	        R				     R
 *	        |				     |
 *	        C				     A
 *	      /   \				   /   \
 *	    A       Z			 W       C
 *	   / \    				        / \
 *	  W   B   				       B   Z
 *	     / \				      / \
 *	    X   Y				     X   Y
 */
static void
__cl_map_rot_right(
	IN	cl_qmap_t* const		p_map,
	IN	cl_map_item_t* const	p_item )
{
	cl_map_item_t	**pp_root;

	ASSERT( p_map );
	ASSERT( p_item );
	ASSERT( p_item->p_left != p_map->nil_item );

	/* Point R to A instead of C. */
	pp_root = __cl_map_get_parent_ptr_to_item( p_item );
	(*pp_root) = p_item->p_left;
	/* Set A's parent to R. */
	(*pp_root)->p_up = p_item->p_up;

	/* Set C's left to B */
	p_item->p_left = (*pp_root)->p_right;
	/*
	 * Set B's parent to C.  We trap for B being NIL since the
	 * caller may depend on NIL not changing.
	 */
	if( (*pp_root)->p_right != p_map->nil_item )
		(*pp_root)->p_right->p_up = p_item;

	/* Set A's right to C. */
	(*pp_root)->p_right = p_item;
	/* Set C's parent to A. */
	p_item->p_up = *pp_root;
}

/*
 * Balance a tree starting at a given item back to the root.
 */
static void
__cl_map_ins_bal(
	IN	cl_qmap_t* const	p_map,
	IN	cl_map_item_t*		p_item )
{
	cl_map_item_t*		p_grand_uncle;

	ASSERT( p_map );
	ASSERT( p_item );
	ASSERT( p_item != p_map->root );

	while( p_item->p_up->color == CL_MAP_RED )
	{
		if( __cl_map_is_left_child( p_item->p_up ) )
		{
			p_grand_uncle = p_item->p_up->p_up->p_right;
			ASSERT( p_grand_uncle );
			if( p_grand_uncle->color == CL_MAP_RED )
			{
				p_grand_uncle->color = CL_MAP_BLACK;
				p_item->p_up->color = CL_MAP_BLACK;
				p_item->p_up->p_up->color = CL_MAP_RED;
				p_item = p_item->p_up->p_up;
				continue;
			}

			if( !__cl_map_is_left_child( p_item ) )
			{
				p_item = p_item->p_up;
				__cl_map_rot_left( p_map, p_item );
			}
			p_item->p_up->color = CL_MAP_BLACK;
			p_item->p_up->p_up->color = CL_MAP_RED;
			__cl_map_rot_right( p_map, p_item->p_up->p_up );
		}
		else
		{
			p_grand_uncle = p_item->p_up->p_up->p_left;
			ASSERT( p_grand_uncle );
			if( p_grand_uncle->color == CL_MAP_RED )
			{
				p_grand_uncle->color = CL_MAP_BLACK;
				p_item->p_up->color = CL_MAP_BLACK;
				p_item->p_up->p_up->color = CL_MAP_RED;
				p_item = p_item->p_up->p_up;
				continue;
			}

			if( __cl_map_is_left_child( p_item ) )
			{
				p_item = p_item->p_up;
				__cl_map_rot_right( p_map, p_item );
			}
			p_item->p_up->color = CL_MAP_BLACK;
			p_item->p_up->p_up->color = CL_MAP_RED;
			__cl_map_rot_left( p_map, p_item->p_up->p_up );
		}
	}
}

void
ips_cl_qmap_insert_item(
	IN	cl_qmap_t* const		p_map,
	IN	cl_map_item_t* const	p_item )
{
	cl_map_item_t	*p_insert_at, *p_comp_item;
	int compare_res = 0;

	ASSERT( p_map );
	ASSERT( p_item );
	ASSERT( p_map->root->p_up == p_map->root );
	ASSERT( p_map->root->color != CL_MAP_RED );
	ASSERT( p_map->nil_item->color != CL_MAP_RED );

	/* Find the insertion location. */
	p_insert_at = p_map->root;
	p_comp_item = __cl_map_root( p_map );

	while( p_comp_item != p_map->nil_item )
	{
		p_insert_at = p_comp_item;

		/* Traverse the tree until the correct insertion point is found. */
		if( p_item->start < p_insert_at->start )
		{
			p_comp_item = p_insert_at->p_left;
			compare_res = 1;
		} else {
			p_comp_item = p_insert_at->p_right;
			compare_res = -1;
		}
	}

	ASSERT( p_insert_at != p_map->nil_item );
	ASSERT( p_comp_item == p_map->nil_item );

	/* Insert the item. */
	p_item->p_left = p_map->nil_item;
	p_item->p_right = p_map->nil_item;
	p_item->color = CL_MAP_RED;
	if( p_insert_at == p_map->root )
	{
		p_insert_at->p_left = p_item;
	}
	else if( compare_res > 0 ) /* key < p_insert_at->key */
	{
		p_insert_at->p_left = p_item;
	}
	else
	{
		p_insert_at->p_right = p_item;
	}
	/* Increase the count. */
	NTID++;

	p_item->p_up = p_insert_at;

	/*
	 * We have added depth to this section of the tree.
	 * Rebalance as necessary as we retrace our path through the tree
	 * and update colors.
	 */
	__cl_map_ins_bal( p_map, p_item );

	__cl_map_root( p_map )->color = CL_MAP_BLACK;

	/*
	 * Note that it is not necessary to re-color the nil node black because all
	 * red color assignments are made via the p_up pointer, and nil is never
	 * set as the value of a p_up pointer.
	 */
}

static void
__cl_map_del_bal(
	IN	cl_qmap_t* const	p_map,
	IN	cl_map_item_t*		p_item )
{
	cl_map_item_t		*p_uncle;

	while( (p_item->color != CL_MAP_RED) && (p_item->p_up != p_map->root) )
	{
		if( __cl_map_is_left_child( p_item ) )
		{
			p_uncle = p_item->p_up->p_right;

			if( p_uncle->color == CL_MAP_RED )
			{
				p_uncle->color = CL_MAP_BLACK;
				p_item->p_up->color = CL_MAP_RED;
				__cl_map_rot_left( p_map, p_item->p_up );
				p_uncle = p_item->p_up->p_right;
			}

			if( p_uncle->p_right->color != CL_MAP_RED )
			{
				if( p_uncle->p_left->color != CL_MAP_RED )
				{
					p_uncle->color = CL_MAP_RED;
					p_item = p_item->p_up;
					continue;
				}

				p_uncle->p_left->color = CL_MAP_BLACK;
				p_uncle->color = CL_MAP_RED;
				__cl_map_rot_right( p_map, p_uncle );
				p_uncle = p_item->p_up->p_right;
			}
			p_uncle->color = p_item->p_up->color;
			p_item->p_up->color = CL_MAP_BLACK;
			p_uncle->p_right->color = CL_MAP_BLACK;
			__cl_map_rot_left( p_map, p_item->p_up );
			break;
		}
		else
		{
			p_uncle = p_item->p_up->p_left;

			if( p_uncle->color == CL_MAP_RED )
			{
				p_uncle->color = CL_MAP_BLACK;
				p_item->p_up->color = CL_MAP_RED;
				__cl_map_rot_right( p_map, p_item->p_up );
				p_uncle = p_item->p_up->p_left;
			}

			if( p_uncle->p_left->color != CL_MAP_RED )
			{
				if( p_uncle->p_right->color != CL_MAP_RED )
				{
					p_uncle->color = CL_MAP_RED;
					p_item = p_item->p_up;
					continue;
				}

				p_uncle->p_right->color = CL_MAP_BLACK;
				p_uncle->color = CL_MAP_RED;
				__cl_map_rot_left( p_map, p_uncle );
				p_uncle = p_item->p_up->p_left;
			}
			p_uncle->color = p_item->p_up->color;
			p_item->p_up->color = CL_MAP_BLACK;
			p_uncle->p_left->color = CL_MAP_BLACK;
			__cl_map_rot_right( p_map, p_item->p_up );
			break;
		}
	}
	p_item->color = CL_MAP_BLACK;
}

void
ips_cl_qmap_remove_item(
	IN	cl_qmap_t* const		p_map,
	IN	cl_map_item_t* const	p_item )
{
	cl_map_item_t	*p_child, *p_del_item;

	ASSERT( p_map );
	ASSERT( p_item );

	if( p_item == p_map->nil_item )
		return;

	if( (p_item->p_right == p_map->nil_item) || (p_item->p_left == p_map->nil_item ) )
	{
		/* The item being removed has children on at most on side. */
		p_del_item = p_item;
	}
	else
	{
		/*
		 * The item being removed has children on both side.
		 * We select the item that will replace it.  After removing
		 * the substitute item and rebalancing, the tree will have the
		 * correct topology.  Exchanging the substitute for the item
		 * will finalize the removal.
		 */
		p_del_item = ips_cl_qmap_successor(p_map, p_item);
		ASSERT( p_del_item != p_map->nil_item );
	}

	NTID--;

	/* Get the pointer to the new root's child, if any. */
	if( p_del_item->p_left != p_map->nil_item )
		p_child = p_del_item->p_left;
	else
		p_child = p_del_item->p_right;

	/*
	 * This assignment may modify the parent pointer of the nil node.
	 * This is inconsequential.
	 */
	p_child->p_up = p_del_item->p_up;
	(*__cl_map_get_parent_ptr_to_item( p_del_item )) = p_child;

	if( p_del_item->color != CL_MAP_RED )
		__cl_map_del_bal( p_map, p_child );

	/*
	 * Note that the splicing done below does not need to occur before
	 * the tree is balanced, since the actual topology changes are made by the
	 * preceding code.  The topology is preserved by the color assignment made
	 * below (reader should be reminded that p_del_item == p_item in some cases).
	 */
	if( p_del_item != p_item )
	{
		/*
		 * Finalize the removal of the specified item by exchanging it with
		 * the substitute which we removed above.
		 */
		p_del_item->p_up = p_item->p_up;
		p_del_item->p_left = p_item->p_left;
		p_del_item->p_right = p_item->p_right;
		(*__cl_map_get_parent_ptr_to_item( p_item )) = p_del_item;
		p_item->p_right->p_up = p_del_item;
		p_item->p_left->p_up = p_del_item;
		p_del_item->color = p_item->color;
	}

	ASSERT( p_map->nil_item->color != CL_MAP_RED );
}

cl_map_item_t *
ips_cl_qmap_successor(
	IN	cl_qmap_t* const		p_map,
	IN	const cl_map_item_t*		p_item )
{
	cl_map_item_t	*p_tmp;

	p_tmp = p_item->p_right;
	if (p_tmp != p_map->nil_item) {
		while (p_tmp->p_left != p_map->nil_item)
			p_tmp = p_tmp->p_left;
		return p_tmp;
	} else {
		p_tmp = p_item->p_up;
		while (p_tmp->p_right == p_item) {
			p_item = p_tmp;
			p_tmp = p_tmp->p_up;
		}
		if (p_tmp == p_map->root)
			return p_map->nil_item;
		return p_tmp;
	}
}

cl_map_item_t *
ips_cl_qmap_predecessor(
	IN	cl_qmap_t* const		p_map,
	IN	const cl_map_item_t*		p_item )
{
	cl_map_item_t	*p_tmp;

	p_tmp = p_item->p_left;
	if (p_tmp != p_map->nil_item) {
		while (p_tmp->p_right != p_map->nil_item)
			p_tmp = p_tmp->p_right;
		return p_tmp;
	} else {
		p_tmp = p_item->p_up;
		while (p_tmp->p_left == p_item) {
			p_item = p_tmp;
			p_tmp = p_tmp->p_up;
		}
		if (p_tmp == p_map->root)
			return p_map->nil_item;
		return p_tmp;
	}
}

/*
 * return the first node with buffer overlapping or zero.
 */
cl_map_item_t *
ips_cl_qmap_search(cl_qmap_t * const p_map,
		unsigned long start, unsigned long end)
{
	cl_map_item_t *p_item, *p_tmp;

	ASSERT( p_map );
	p_item = __cl_map_root(p_map);

	while (p_item != p_map->nil_item) {
		if (start > p_item->start) {
			p_tmp = p_item->p_right;
			if (p_tmp != p_map->nil_item) {
				p_item = p_tmp;
				continue;
			}

			/*
			 * p_item is on immediate left side of 'start'.
			 */
			if (start >= (p_item->start+(p_item->length<<12))) {
				/*
				 * p_item is on immediate right
				 * side of 'start'.
				 */
				p_item = ips_cl_qmap_successor(p_map, p_item);
				if (p_item != p_map->nil_item &&
						end <= p_item->start)
					p_item = p_map->nil_item;
			}
		} else if (start < p_item->start) {
			p_tmp = p_item->p_left;
			if (p_tmp != p_map->nil_item) {
				p_item = p_tmp;
				continue;
			}

			/*
			 * p_tmp is on immediate left side of 'start'.
			 */
			p_tmp = ips_cl_qmap_predecessor(p_map, p_item);
			if (p_tmp == p_map->nil_item ||
			(start >= (p_tmp->start+(p_tmp->length<<12)))) {
				/*
				 * p_item is on immediate right
				 * side of 'start'.
				 */
				if (end <= p_item->start)
					p_item = p_map->nil_item;
			} else
				p_item = p_tmp;
		}

		break;
	}

	return p_item;
}
